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
//! in memory alone ([`HeldQueue::in_memory`]: a directory out of reach,
//! §3c.3) no copy is made, and a close loses the lines. A line whose copy is
//! refused stands in the queue all the same, and waits (below). A re-mark
//! that changes nothing is no line at all. A line kept at a position raises
//! to it the `base` of
//! every line held after it on its document
//! ([`HeldQueue::done`]), in the queue as the `done` is written and again at
//! a reopen from that `done` line, so no line is rewritten to carry it
//! (§3c.2). The person's `send` on a moved document raises a line's `base`
//! to the position the board's verdict read through
//! ([`HeldQueue::remark_raised`], §3c.4): a `held` line of its ordinal
//! carrying the raised base beside its new reason, which the reader takes in
//! the earlier line's place as it takes a re-mark. Neither raise lowers a
//! base: a base already past the position stands, and a later `done` kept
//! below a raised base leaves it. A line's frame is rewritten by one act
//! alone, the shift of a burst the board refused as typed against an older
//! state of its document ([`HeldQueue::rewrite`], skep #442): a `held` line
//! of its ordinal carrying the shifted frame, synced before the shifted
//! frame is dialed, so a relaunch reads the positions the shell last sent,
//! never the page's.
//!
//! **A refused copy waits, and every line after it** (§3c.3; skep #813). A
//! line whose first copy is refused — by the device, its write cut short or
//! its sync refused, its bytes then cut back off the file; or by the writer,
//! a line past [`MAX_HELD_LINE_BYTES`] — has the refusal answered beside it,
//! and it WAITS in memory with every line held after it ([`Waiting`]): none
//! of them is copied ahead of it, so the file never holds a line without
//! every line standing before it, and a reopen never resends a burst ahead
//! of the one it was composed after. The retry ([`HeldQueue::retry`]) copies
//! the waiting lines in `k` order, each whole in its state now — a re-mark
//! or a shift made while it waited carried in its first copy, spending none
//! of the re-mark budget, as the reader counts a line's first copy — and
//! stops at the first copy refused again, the lines waiting on from that
//! one. It runs before every copy the queue makes — a hold's, a re-mark's, a
//! shift's, a `done`'s and a join's — and the shell runs it at every probe
//! of the board, whatever the board's state, so space freed while no one
//! types is enough. A waiting line that leaves the queue writes no `done`,
//! nothing of it standing on disk; a join meeting a waiting line enters
//! nothing. A close before the retry lands loses the waiting lines.
//!
//! **The pending directory** (§3c.1; skep #725). A board whose head record
//! stands and cannot be read, or a claimed board serving none — the shell's
//! `head_unreadable` hold (SP-14) — names no chain yet, so its lines go to
//! `held/pending/<hash>/principal-<n>.held`, `<hash>` the lowercase hex
//! SHA-256 of the origin dialed, as `Board::dialed` spells it
//! ([`HeldDir::pending`]), 64 hex as a chain's name is: the one directory
//! here named by an origin, the design's rule that no file here is bent for
//! it alone (§3c.1, §9 item 43). Its file is the chain file's in every member
//! save two — the header's `v` is 2 and its `board` the origin dialed — and
//! its lines are the chain file's lines, unchanged, each synced before its
//! answer as a chain file's is, so a close loses none and a relaunch that
//! dials the same origin finds them. Its reader is [`HeldDir::open_file`] in
//! the directory's own mode: it accepts `v` 2 alone — a `v` above it halts
//! `Newer`, any other `v` the unknown-member face — and a `board` equal to
//! the origin dialed, another origin's file set aside by the same
//! non-overwriting rename under the hash of the origin it names; the chain
//! directory's reader is untouched, so a pending file misplaced into a chain
//! directory halts `Newer`. Once `H.1` reads, the pending file's standing
//! lines JOIN the board's own queue ([`HeldQueue::join`]) line by line in
//! `k` order, each written and synced there first, and only then is the
//! pending file removed ([`HeldQueue::remove_file`]): a crash between leaves
//! both, and the next join re-runs — a line a standing chain line already
//! carries, by `doc`, `id` and frame and never by ordinal, is not entered
//! again, so nothing is doubled. Where the chain queue holds no line and its
//! next ordinal is at or below the pending lines' first, each line keeps its
//! ordinal and the chain queue's next is set past them; otherwise the lines
//! are renumbered from the chain queue's next ordinal in order, and the hold
//! re-says `held` for their documents, so a page or an agent reads the new
//! ordinals before it acts on one. A copy the device refuses mid-join undoes
//! the join — every line it entered `done … dropped`, the pending file
//! standing for the next launch's — so a line is never half on each side. A
//! queue kept in memory alone joins by the same rule, so no line waits for
//! an empty queue to reach disk.
//!
//! **The file is primary** (PATTERNS P38; §3c.3). A newer `v`, an unknown
//! header member, or a middle line that is not a whole line of the two
//! forms — not UTF-8, not a JSON object, a member missing or of another
//! type, a `doc` that is no document address, anchors past
//! [`MAX_ANCHOR_BYTES`], an ordinal past [`MAX_ORDINAL`], a line past
//! [`MAX_HELD_LINE_BYTES`] — halts this principal's writing at this board
//! naming the path, and so does a whole header line that is no JSON object,
//! names another `type` or carries no `v` of 1 or more: never rebuilt over a
//! whole line, never moved, never removed. A misplaced file (header `board`
//! not the directory's chain, or `principal` not the file's name) is moved
//! aside by a rename that never overwrites (`aside_name`'s form, the index's
//! idiom), this principal's file started fresh.
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
//! **The store's budgets, on what a hold adds.** A line's anchors are bounded
//! at their one door ([`Anchors::of`]) by [`MAX_ANCHOR_BYTES`], the bridge's
//! argument and the held file's member alike, as the burst's door bounds its
//! frame by the board's frame cap. No line is held that would carry the
//! queue's standing frames and anchors past [`MAX_HELD_BYTES`], four frames
//! and one line's anchors at their bounds, or its lines past
//! [`MAX_HELD_LINES`] — a line past either refused and kept nowhere. Both are
//! defence bounds far past any outage a person meets (§3c.3), set where a
//! launch's reopen and the resend's walk at them measure a few seconds
//! ([`MAX_HELD_LINES`] states the figures). A reopened queue is read
//! whole, past either budget where its file is past it (a `done` the device
//! refused leaves its line on disk, and a file another writer made may hold
//! any number), and holds nothing more until it drains below them. Each line
//! is bounded by [`MAX_HELD_LINE_BYTES`] at the writer and the reader alike;
//! the re-marks one file copies within [`MAX_HELD_REMARK_BYTES`], a re-mark
//! past them taken in the queue alone and the mark of a line `sent` spending
//! none of them; and the file is read line by line, keeping the standing
//! lines alone — so an open holds the queue it reads, never the file's
//! history of lines done.
//!
//! **The lock** `held/<chain>/lock` (the key store's `flock` idiom, copied
//! from `search::directory::BoardDir::try_lock` — the index directory's type
//! is the index's) is held for the shell's life: ONE SHELL PER DATA
//! DIRECTORY (§3c.3), the lock the holder's guard for the instant a second
//! launch's hand-off has not yet closed — a shell finding it held opens no
//! file there and reads alone at the board, every write refused at its door
//! (`another_window`), and tries again at its next session's open.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use skep_client::Origin;
use skep_search::{aside_name, Chain};
use skep_util::file::{self, Appender, LineReader, Next, OnTail};

use crate::wire::{document_address, json_len, within_components, MAX_FRAME_BYTES};

/// The lock file's name, the key store's idiom (`search.md` §5.6).
const LOCK_NAME: &str = "lock";

/// The most bytes a line's anchors may spell: the board's frame cap.
///
/// It is the bound [`Anchors::of`] holds the page's anchors to (SP-17), at
/// the bridge's door and at the held file's reader alike: the length of
/// their compact JSON, the spelling the bridge and the held file give them.
/// The page reads its anchors off one `image` answer — at most the board's
/// run budget of runs, each an I-address the board minted and a width — so
/// honest anchors are kilobytes, far under it. Anchors past the bound are of
/// no form: the bridge refuses them `malformed_args` naming `anchors`, and
/// the reader halts on a line carrying them.
pub const MAX_ANCHOR_BYTES: usize = MAX_FRAME_BYTES;

/// The queue's budget: four frames and one line's anchors, each at its bound.
///
/// It is the most bytes a hold lets a principal's standing lines' frames
/// and anchors come to at one board — four of the board's own frame cap,
/// [`MAX_FRAME_BYTES`], beside [`MAX_ANCHOR_BYTES`] — so a burst the burst's
/// door admits, its anchors of their form, always fits a queue holding none,
/// and three more frames at the cap fit beside it. It is a defence bound far
/// past any outage a person meets (§3c.3): the design's estimate is that
/// hours of typing are kilobytes, orders of magnitude under it; a queue past
/// it is a page holding without bound — every frame and its anchors copied
/// to disk and read back at the next open — so the line that would pass it
/// is refused, and kept nowhere. The bytes cost a launch's read little
/// beside the lines: a file at both budgets is read in the figures
/// [`MAX_HELD_LINES`] states. A reopened queue is read whole, past it where
/// its file is, and holds no line more until it drains below it.
pub const MAX_HELD_BYTES: usize = 4 * MAX_FRAME_BYTES + MAX_ANCHOR_BYTES;

/// The most bytes one line of a held file may carry, its `\n` aside.
///
/// The bound holds at the writer and at the reader alike, and is spelled
/// from the bounds of a line's own members, never from the queue's budget.
/// A `held` line spells its frame (within [`MAX_FRAME_BYTES`], the burst's
/// door's bound) and beside it the frame's own `doc` and `id` again, a
/// second frame's worth at most, its anchors (within [`MAX_ANCHOR_BYTES`]),
/// and room over for its cause and a board's verdict as a daemon answers one
/// (a few hundred bytes). The writer copies no longer line — the queue keeps
/// it, unwritten, as it keeps a line the device refused — and the reader
/// halts on one as damaged, reading no more of it than one byte past the
/// bound.
const MAX_HELD_LINE_BYTES: usize = 2 * MAX_FRAME_BYTES + MAX_ANCHOR_BYTES + 64 * 1024;

/// The most lines a hold lets a principal's queue come to at one board.
///
/// It is the queue's line budget, a defence bound far past any outage a
/// person meets (§3c.3): the burst machine coalesces each pause's keystrokes
/// into one burst, and at a burst per ten bytes typed, 16384 lines is some
/// eleven hours of continuous typing at forty words a minute. Past it a line
/// is refused `held_full`, as one past the bytes is. A reopened queue is read
/// whole, past it where its file is, and holds no line more until it drains
/// below it.
///
/// **What it bounds.** A line costs the same whatever its frame holds, and
/// the byte budget alone admits millions of empty bursts held behind one
/// refused, so the lines a hold admits bound two costs the bytes do not, each
/// growing at its worst as the square of the lines:
///
/// * the reopen's read at a launch ([`HeldDir::open_file`]), each `done` kept
///   at a position raising the lines standing after it on its document;
/// * the resend's walk on the board's feed thread, each line it settles taken
///   out of the queue ([`HeldQueue::done`]) and the lines after it on its
///   document raised, and each document's lines found and counted for its
///   `held` event.
///
/// **Measured** on an Apple M1 Max, the figures the budget is set by, at it
/// and [`MAX_HELD_BYTES`] (`held`'s and `hold`'s timing cells): a drained
/// file — every line on one document held, marked `sent` and kept at a
/// position by a `done`, the last refused — reopens in 1.1 s optimized and
/// 11 s unoptimized; the walk's own work over a full queue in memory, the
/// board answering at once and no attest owed, takes 1.8 s with every line on
/// one document and 2.9 s with each on its own, 10 s and 16 s unoptimized.
/// At twice the lines, optimized, the reopen takes 6.2 s and the walk 10 s
/// and 21 s, past a few seconds. A drain also pays each line's send, as a
/// burst never held pays it but for the copies: the attest a signed session
/// composes, the board's write, and the two copies its mark and its `done`
/// sync to the device — about 13 ms a line here, most of it the two copies.
pub const MAX_HELD_LINES: usize = 16384;

/// The ceiling the timing cells hold a reopen and a walk at the budgets to.
///
/// It is five times the slowest figure [`MAX_HELD_LINES`] states for the
/// build's profile — 2.9 s optimized, 16 s unoptimized — and loose on
/// purpose, as a flaky bound is wrong and a loose one honest: the load of a
/// full gate's parallel run stays under it, and a cost grown by another power
/// of the lines does not.
#[cfg(test)]
pub(crate) const TIMED_CEILING: std::time::Duration = std::time::Duration::from_secs(if cfg!(debug_assertions) { 80 } else { 15 });

/// The most bytes of re-mark lines one file copies, creation to compaction.
///
/// It is the re-mark budget, each line counted as [`MAX_HELD_LINE_BYTES`]
/// counts a line. A re-mark copies its whole line, frame, anchors and all,
/// under the new reason, and the board's answers choose the reasons: a board
/// answering each probe with another hold-class cause would grow the file
/// by a synced line at every probe for as long as it answers so, for a few
/// hundred bytes of answer each. An honest outage re-marks a document's head
/// a handful of times as the board's state and the person's acts move it,
/// and its text is kilobytes (§3c.3), so one line bound holds its re-marks
/// many times over — a head of kilobytes re-marked thousands of times, the
/// largest line the writer copies re-marked once. A shift of the line's
/// frame ([`HeldQueue::rewrite`]) spends the budget a whole frame too, as a
/// re-mark does, and the hold bounds the shifts a line takes; a raise of its
/// base at the person's `send` ([`HeldQueue::remark_raised`]) is a re-mark,
/// and spends it as one. Past it a re-mark is taken in the queue alone, its
/// copy refused as a copy the device refused is ([`HeldQueue::remark`]): a
/// reopen reads the reason — and the frame and the base — copied last, and
/// the resend's read decides the line from there.
///
/// **The mark of `sent` spends none of it** (`marks_sent`). A resend marks
/// its line `sent` before it dials (§3c.2), and a drain of a full queue
/// marks every line in it, copying up to [`MAX_HELD_BYTES`] of re-mark lines,
/// past this budget; a mark refused would relaunch a line whose dial may have
/// landed as one never sent, which the resend sends again without the read
/// for its landing, and the person's text would land twice. A line is marked
/// once after its hold, and again only after a re-mark lowered its `sent` and
/// spent the budget, so the marks one file copies are bounded by the lines it
/// holds and by the budget.
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
/// It holds the line's `cause`, the verdict beside a refused run's or a
/// moved line's the board refused, and whether the burst may have landed —
/// the three members a hold writes and a re-mark rewrites together.
#[derive(Debug, Clone, PartialEq)]
pub struct Reason {
    /// A token of §3c.4's table, the shell's `head_unreadable` or
    /// `session_died`, or a refused run's own token.
    ///
    /// A refused run's token is the board's — a refusal at a resend under a
    /// code the shell's table holds nowhere among them, handed to the person
    /// at once — or the shell's `answers_lost` where it handed the person a
    /// line no landing of which was found two minutes after its first failed
    /// send. `head_unreadable` holds a signed write whose signature could not
    /// be made, until the board's head record reads again (SP-14);
    /// `session_died` a burst whose dial met the death signal, until a
    /// session of its principal's that may write stands (§3c.4).
    pub cause: String,
    /// The verdict beside a refused run's line, or a held line's reason.
    ///
    /// It is the board's verbatim, or the shell's `answers_lost` refusal
    /// where it handed the line to the person at its deadline, its `last` the
    /// last failure's token — the held cause, or the board's — and its
    /// `elapsed_ms` the time since the line's first failed send (§3c.4); at a
    /// line the board refused as typed against an older state of its document,
    /// held `moved`, the board's `arrangement_moved` verbatim, naming the
    /// state the burst was typed against and the document's current one; at
    /// a line held `head_unreadable`, the shell's refusal naming why the
    /// signature could not be made, the line holding all the same; at a line
    /// held `session_died`, the shell's `session_died` refusal once the
    /// session's end derives the death, its `reason` the death's arm, the
    /// line holding all the same.
    pub refusal: Option<Value>,
    /// Whether the burst may have landed.
    ///
    /// It is whether a dial of this line was attempted since the last read,
    /// so it may have landed: a first dial whose answer was lost (`Timeout`,
    /// `Io`, `Truncated`, `Response`, `TooLarge` or a later transport error,
    /// or the board's `500 internal_panic`), or met a `poisoned` answer,
    /// whose frames the board's journal keeps for its restart; and every
    /// resend, which marks its line before it dials, synced, so a crash or a
    /// refused write between the dial and its answer leaves the line read as
    /// one that may have landed. It is `false` for a line held before any
    /// dial, or whose first dial reached no board or met its refusal — the
    /// death signal among them, a dead token's write committing nothing —
    /// until a resend of it is attempted. A re-mark keeps it, whatever that
    /// resend answers: one that never left, or one the board refused, says
    /// nothing of an earlier dial's write. A moved document's lines keep
    /// theirs, a line handed to the person keeps it too, and `resolve(send)`
    /// keeps every line's own, so a line that may have landed reads before
    /// it is sent again (§3c.5).
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

/// The identities a burst's edit is placed by (skep #442, #751).
///
/// They are the page's, sent over the bridge beside the frame and kept with
/// the held line, never on the wire: `before` the I-address of the unit just
/// before the span the burst edits, `after` the I-address of the unit just
/// after it, each `None` at the document's edge — an insert at the first
/// position has no unit before it, one at the end none after — and `span`
/// the I-runs of the units the span holds, in V-order, as the page's `image`
/// read gave them: present for a delete and a rearrange, whose span holds
/// units, and absent for an insert, a copy and a reinstate, which place at a
/// point. Where the board refuses the burst as typed against an older state
/// of its document, the shell finds `before` and `after` in the document's
/// current image and, where the units between them are the span's own —
/// none for a placement, so the two stand adjacent — moves every position
/// the burst names by their one displacement and sends it again
/// (`hold::resend`); a burst that carries none — an agent's through the MCP
/// tools — is held as a moved document, and so is a delete or a rearrange
/// that carries no `span`. Made by [`Anchors::of`] alone, from the bridge's
/// argument and from the held file's member alike, so every anchor kept is
/// an I-address in the tumbler-string form the shift splits ([`i_address`])
/// and every run of a span one [`SpanRun`] admits (SP-18), and the whole
/// spells no more than [`MAX_ANCHOR_BYTES`] (SP-17), its bytes counted there
/// once for the queue's budget ([`Anchors::bytes`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchors {
    /// The I-address of the unit just before the span; `None` at the start.
    pub before: Option<String>,
    /// The I-address of the unit just after the span; `None` at the end.
    pub after: Option<String>,
    /// The I-runs of the units the span holds, in V-order.
    ///
    /// It is `None` where the page names none, as it names none for a
    /// placement at a point.
    pub span: Option<Vec<SpanRun>>,
    /// The length of the anchors' compact JSON, within [`MAX_ANCHOR_BYTES`].
    bytes: usize,
}

impl Anchors {
    /// Returns the anchors `v` spells, where it is of their form.
    ///
    /// The form is `{before, after, span?}`, `before` and `after` present,
    /// each `null` or an I-address ([`i_address`]), `span` absent or a
    /// non-empty list of runs of [`SpanRun`]'s form, and nothing beside the
    /// three, the whole spelling no more than [`MAX_ANCHOR_BYTES`] as compact
    /// JSON — measured first, before any member is read; any other value is
    /// of no form, which the bridge refuses `malformed_args` naming `anchors`
    /// and the held file's reader halts on.
    pub fn of(v: &Value) -> Option<Anchors> {
        let bytes = json_len(v);
        if bytes > MAX_ANCHOR_BYTES {
            return None;
        }
        let m = v.as_object().filter(|m| m.keys().all(|k| matches!(k.as_str(), "before" | "after" | "span")))?;
        let anchor = |name: &str| match m.get(name)? {
            Value::Null => Some(None),
            Value::String(text) if i_address(text).is_some() => Some(Some(text.clone())),
            _ => None,
        };
        let span = match m.get("span") {
            None => None,
            Some(Value::Array(runs)) if !runs.is_empty() => Some(runs.iter().map(SpanRun::of).collect::<Option<Vec<_>>>()?),
            Some(_) => return None,
        };
        Some(Anchors { before: anchor("before")?, after: anchor("after")?, span, bytes })
    }

    /// Returns the anchors as the bridge and the held file spell them.
    pub fn json(&self) -> Value {
        let mut v = json!({"before": self.before, "after": self.after});
        if let Some(span) = &self.span {
            v["span"] = span.iter().map(SpanRun::json).collect();
        }
        v
    }

    /// Returns the bytes the anchors spell, within [`MAX_ANCHOR_BYTES`].
    ///
    /// It is the length of their compact JSON as [`Anchors::of`] measured
    /// it, which is the length of their spelling on the bridge and in the
    /// held file ([`Anchors::json`]): the form's members are `null`, strings
    /// of digits and dots and its own names, none escaped, so two spellings
    /// of the one value differ in their members' order alone. It is what a
    /// line's anchors spend of the queue's budget ([`MAX_HELD_BYTES`]).
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

/// Returns anchors of their form whose compact JSON is `bytes` long.
///
/// They are a `before` of three components, its middle one as long as the
/// length asks, and no `after`: a suite's anchors at a bound, or past it.
///
/// # Panics
///
/// Panics where `bytes` is under 31, the shortest such anchors spell.
#[cfg(test)]
pub(crate) fn anchors_spelled(bytes: usize) -> Value {
    let middle = bytes.checked_sub(30).filter(|n| *n >= 1).expect("anchors of three components spell 31 bytes at least");
    json!({"before": format!("1.{}.1", "1".repeat(middle)), "after": null})
}

/// One I-run of the units a burst's span holds (skep #751).
///
/// It is `width` units of I-space from the I-address `start`, as an `image`
/// read answers a run. Made by `SpanRun::of` alone, through [`Anchors::of`]:
/// `start` an I-address ([`i_address`]), `width` a natural of 1 or more, and
/// every unit's last component — `start`'s plus one less than `width` — within
/// a `u64`, so the shift compares it with the image's runs and checks nothing
/// again (SP-18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpanRun {
    /// `start` less its last component.
    prefix: String,
    /// `start`'s last component: the first unit's.
    first: u64,
    /// The units the run holds, 1 or more.
    width: u64,
}

impl SpanRun {
    /// Returns the run `v` spells, where it is of its form.
    ///
    /// The form is `{start, width}`, both present and nothing beside them,
    /// `start` an I-address and `width` a natural of 1 or more in its one
    /// decimal spelling, as the wire spells a natural; any other value is of
    /// no form.
    fn of(v: &Value) -> Option<SpanRun> {
        let m = v.as_object().filter(|m| m.len() == 2)?;
        let (prefix, first) = i_address(m.get("start")?.as_str()?)?;
        let width = m.get("width")?.as_str().filter(|w| natural(w))?.parse::<u64>().ok().filter(|w| *w >= 1)?;
        first.checked_add(width - 1)?;
        Some(SpanRun { prefix: prefix.to_string(), first, width })
    }

    /// Returns the run as the shift compares runs.
    ///
    /// It is its I-prefix, its first unit's last component and its width:
    /// the three of an `image` run.
    pub fn extent(&self) -> (&str, u64, u64) {
        (&self.prefix, self.first, self.width)
    }

    /// Returns the run's `start` in its one spelling.
    ///
    /// It is the spelling [`SpanRun::of`] read: an I-address's components
    /// carry no leading zero, so its prefix and last component spell it.
    fn start(&self) -> String {
        format!("{}.{}", self.prefix, self.first)
    }

    /// Returns the run as the bridge and the held file spell it.
    fn json(&self) -> Value {
        json!({"start": self.start(), "width": self.width.to_string()})
    }
}

/// Returns whether `text` is a natural in its one decimal spelling.
///
/// The spelling is digits alone, with no leading zero.
fn natural(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) && (text == "0" || !text.starts_with('0'))
}

/// Splits an I-address at its last component: the prefix, and the last
/// component as the number a run's positions advance along.
///
/// The text is a tumbler in its dotted-decimal spelling within the
/// component budget, of two components at least, every component a
/// natural with no leading zero, the last one fitting a `u64`; any other
/// text is no I-address, and `None`. It is the split the shift finds an
/// anchor in a run by: a run `image` answers is `i_start` and a width, its
/// positions `prefix.(last + n)` for `n` below the width.
pub fn i_address(text: &str) -> Option<(&str, u64)> {
    if !within_components(text) || !text.split('.').all(natural) {
        return None;
    }
    let (prefix, last) = text.rsplit_once('.')?;
    Some((prefix, last.parse().ok()?))
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
    /// The `since` of the resend's read (§3c.5): the position the read of
    /// the line's own landing starts from, its one job.
    ///
    /// It is the position of its principal's latest write on `doc` that the
    /// shell knew when the burst was sent — its ack's, or the landing the
    /// resend's read found — or else the open position of the session it is
    /// held under (§3c.2), read before the burst's dial so it is never past
    /// the line's own landing. A line held before it on `doc` and kept at a
    /// later position raises it to that position ([`HeldQueue::done`]), so
    /// its read starts past that landing; and the person's `send` on a moved
    /// document raises it to the position the board's verdict read through
    /// ([`HeldQueue::remark_raised`], §3c.4), so its read starts past the
    /// rows the person acknowledged, none of them its landing — a line is
    /// held moved by the board's verdict on a dial alone, after the read for
    /// its own landing. An ack of a later write raises it never: the read
    /// takes no row for a move, and a row of the shell's own that is not the
    /// line's landing is no verdict.
    pub base: u64,
    /// The wire frame, with no `attest` (§3c.2): the page's as composed, or
    /// as the shell last shifted it ([`HeldQueue::rewrite`]).
    pub frame: Value,
    /// The page's anchors, where the burst carried them (skep #442, #751).
    ///
    /// They bound the span the frame edits by identity, and name the units a
    /// delete's or a rearrange's span holds, for the shift; a burst that
    /// carried none is held as a moved document where the board refuses it
    /// as typed against an older state.
    pub anchors: Option<Anchors>,
    /// Why the line is held.
    pub reason: Reason,
    /// The append's wall-clock unix milliseconds.
    pub time: u64,
}

impl HeldLine {
    /// Returns the bytes the line spends of its queue's budget.
    ///
    /// They are its frame's and its anchors' ([`MAX_HELD_BYTES`]'s count):
    /// what the open sums, a rewrite recounts, a settle gives back and a
    /// join adds, as the hold added them.
    fn held_bytes(&self) -> usize {
        json_len(&self.frame) + self.anchors.as_ref().map_or(0, Anchors::bytes)
    }
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

/// The directory `held/<chain>/` or `held/pending/<hash>/`, a principal's
/// file opened under it.
///
/// It is ensured `0700` and locked once for the shell's life — a board's own
/// directory for it, the pending one until the board's `H.1` reads (the
/// module doc).
#[derive(Debug, Clone)]
pub struct HeldDir {
    path: PathBuf,
    named: Named,
}

/// What names a held directory, and the header's `board` and `v` with it.
///
/// A file's header spells the name the directory is keyed by, so a file
/// copied into the wrong directory is told from its header alone.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Named {
    /// `held/<chain>/`: a board's own, named by `H.1`'s chain.
    ///
    /// Its header's `v` is 1 and its `board` the chain.
    Chain(Chain),
    /// `held/pending/<hash>/`: a board's whose `H.1` will not read, named by
    /// the hash of the origin dialed (the module doc).
    ///
    /// Its header's `v` is 2 and its `board` the origin.
    Pending { origin: String, hash: Chain },
}

impl Named {
    /// Returns the header's `v` a file of this directory carries.
    fn v(&self) -> u64 {
        match self {
            Named::Chain(_) => 1,
            Named::Pending { .. } => 2,
        }
    }

    /// Returns the header's `board` a file of this directory carries.
    fn board(&self) -> String {
        match self {
            Named::Chain(chain) => chain.to_string(),
            Named::Pending { origin, .. } => origin.clone(),
        }
    }

    /// Returns the directory's own 64-hex name: the chain, or the hash.
    fn hex(&self) -> Chain {
        match self {
            Named::Chain(chain) => *chain,
            Named::Pending { hash, .. } => *hash,
        }
    }

    /// Returns the name a misplaced file is set aside under: its own, where
    /// its header's `board` spells one, else the directory's.
    ///
    /// A chain directory's aside carries the file's own chain; a pending
    /// directory's the hash of the origin the file names, the form its
    /// directory would be named by.
    fn aside_of(&self, board: Option<&str>) -> Chain {
        match self {
            Named::Chain(_) => board.and_then(Chain::parse).unwrap_or_else(|| self.hex()),
            Named::Pending { .. } => board.map_or_else(|| self.hex(), origin_hash),
        }
    }
}

/// Returns the pending directory's name for `origin`: the lowercase hex
/// SHA-256 of the origin as `Board::dialed` spells it, 64 hex as a chain is.
fn origin_hash(origin: &str) -> Chain {
    Chain::from_bytes(Sha256::digest(origin.as_bytes()).into())
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
/// object, `anchors` of their form ([`Anchors::of`]) where present — absent
/// on a line whose burst carried none, and their `span` absent where they
/// name none — `refusal` any value where present, a `null` one read as none.
fn parse_held_line(k: u64, mut m: Map<String, Value>) -> Option<HeldLine> {
    let doc = m.get("doc")?.as_str().filter(|d| document_address(d).is_some())?.to_string();
    let id = match m.remove("id") {
        None => None,
        Some(Value::String(id)) => Some(id),
        Some(_) => return None,
    };
    let frame = m.remove("frame").filter(Value::is_object)?;
    let anchors = match m.remove("anchors") {
        None => None,
        Some(v) => Some(Anchors::of(&v)?),
    };
    let reason = Reason {
        cause: m.get("cause")?.as_str()?.to_string(),
        refusal: m.remove("refusal").filter(|r| !r.is_null()),
        sent: m.get("sent")?.as_bool()?,
    };
    Some(HeldLine { k, doc, id, base: m.get("base")?.as_u64()?, frame, anchors, reason, time: m.get("time")?.as_u64()? })
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
/// which the read of a line behind it starts past — a line behind is never
/// dialed while the kept line stands, so no landing of its own lies below
/// `at`. A base already past `at` stands.
fn raise_bases<'a>(behind: impl Iterator<Item = &'a mut HeldLine>, doc: &str, at: u64) {
    for line in behind.filter(|line| line.doc == doc) {
        line.base = line.base.max(at);
    }
}

/// Returns whether a re-mark from `was` to `now` marks its line `sent`.
///
/// It is the one rule the writer ([`HeldQueue::remark`]) and the reader
/// ([`HeldDir::open_file`]) count the re-mark budget by: a re-mark that turns
/// the line's `sent` true spends none of [`MAX_HELD_REMARK_BYTES`], and every
/// other re-mark spends its line.
fn marks_sent(was: &Reason, now: &Reason) -> bool {
    !was.sent && now.sent
}

impl HeldDir {
    /// Returns the directory `<data_dir>/held/<chain>/`.
    ///
    /// `data_dir` is the data directory the index takes (§3c.8), the held
    /// store beside the key store and never under it (§3c.1's `<app data>`).
    pub fn new(data_dir: &Path, chain: Chain) -> HeldDir {
        HeldDir { path: data_dir.join("held").join(chain.to_string()), named: Named::Chain(chain) }
    }

    /// Returns the pending directory `<data_dir>/held/pending/<hash>/` for a
    /// board dialed at `origin` whose `H.1` will not read (the module doc).
    ///
    /// `<hash>` is the lowercase hex SHA-256 of the origin as `Board::dialed`
    /// spells it; its files carry the origin as their header's `board` and
    /// `v` 2, and join the board's own directory once `H.1` reads.
    pub fn pending(data_dir: &Path, origin: &Origin) -> HeldDir {
        let hash = origin_hash(origin.as_str());
        HeldDir { path: data_dir.join("held").join("pending").join(hash.to_string()), named: Named::Pending { origin: origin.as_str().to_string(), hash } }
    }

    /// Returns whether the directory stands on disk.
    ///
    /// A pending directory that does not holds no file of an earlier run's
    /// to join, so the join touches nothing there.
    pub fn exists(&self) -> bool {
        self.path.is_dir()
    }

    /// Returns the `board` the directory's files carry in their header: the
    /// chain, or the origin a pending directory is named by.
    pub fn board(&self) -> String {
        self.named.board()
    }

    /// Returns the principals whose files stand in the directory, in order.
    ///
    /// They are the `principal-<n>.held` files — an earlier run's, where the
    /// directory is a pending one and the join runs — listed through the
    /// tail module's lister (SP-3), which names the files of a suffix no
    /// writer holds a lock on; a held file is held by no lock of its own, the
    /// directory's `lock` being the holder's guard, so every one is listed.
    /// An aside, or any other name, is no principal's file. A directory that
    /// does not stand holds none.
    ///
    /// # Errors
    ///
    /// Returns the directory's read failing, or a file's open.
    pub fn principals(&self) -> io::Result<Vec<u64>> {
        let mut out: Vec<u64> = file::stale(&self.path, ".held")?
            .iter()
            .filter_map(|path| {
                let name = path.file_name()?.to_str()?;
                let n: u64 = name.strip_prefix("principal-")?.strip_suffix(".held")?.parse().ok()?;
                (Self::file_name(n) == name).then_some(n)
            })
            .collect();
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    /// Sets the principal's file aside, as a misplaced file is set aside.
    ///
    /// It is the join's refusal of a pending file whose header names another
    /// board than the one dialed, or of a board's file naming another chain
    /// (the module doc) — the rename that never overwrites, under the name
    /// the file's own `board` gives it ([`Named::aside_of`]).
    ///
    /// # Errors
    ///
    /// Returns the link's I/O error other than a name taken, or the unlink's.
    pub fn set_aside(&self, principal: u64, board: Option<&str>) -> io::Result<PathBuf> {
        self.move_aside(&Self::file_name(principal), &self.named.aside_of(board))
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
    /// [`MAX_HELD_REMARK_BYTES`] as the writer counts them, a line's mark of
    /// `sent` spending none, so a relaunch keeps the file's budget where its
    /// writer left it. The whole lines' bytes are counted
    /// too, so the next line is written where the last of them ends, a torn
    /// tail cut off first; the open itself writes nothing, a tail it meets
    /// left for that cut and answered ([`HeldQueue::torn`]) for the shell
    /// to say once. `account` is the header's where this open writes one; a
    /// header read gives the queue the file's own ([`HeldQueue::account`]).
    ///
    /// **The directory's mode.** The `v` accepted and the `board` a file must
    /// name are the directory's own ([`Named`]): a board's directory reads
    /// `v` 1 and its chain, a pending one `v` 2 and the origin dialed (the
    /// module doc). A `v` above the directory's is the newer face whatever
    /// the directory — a pending file misplaced into a board's directory
    /// among them — and a `v` below it, or none, the unknown-member face; a
    /// `board` that is not the directory's is a misplaced file, set aside
    /// under the name its own `board` gives it ([`Named::aside_of`]).
    ///
    /// # Errors
    ///
    /// Returns the open's I/O error other than a file not found, the read's,
    /// and the move's where a misplaced file cannot be moved aside.
    pub fn open_file(&self, principal: u64, account: &str) -> io::Result<Opened> {
        let path = self.path.join(Self::file_name(principal));
        let disk = Disk { path: path.clone(), named: self.named.clone(), principal, account: account.to_string(), created: false, headless: false, torn: None, whole_bytes: 0, remark_bytes: 0, waiting: None };
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
        // `v` read first (§3c.2): a `v` above the directory's own is the
        // newer face, never half-read; any other `v` is a header off this
        // directory's spelling.
        let own_v = self.named.v();
        match header.get("v").and_then(Value::as_u64) {
            Some(v) if v == own_v => {}
            Some(v) if v > own_v => return halted(HaltWhy::Newer),
            _ => return halted(HaltWhy::UnknownMember),
        }
        // No unknown member, and the type pinned.
        if header.get("type").and_then(Value::as_str) != Some("skep-held-bursts") {
            return halted(HaltWhy::UnknownMember);
        }
        if header.keys().any(|k| !matches!(k.as_str(), "type" | "v" | "board" | "principal" | "account")) {
            return halted(HaltWhy::UnknownMember);
        }
        // A misplaced file — header `board` not the directory's own (its
        // chain, or the origin a pending directory is named by), or
        // `principal` not the file's name — moved aside, this file started
        // fresh.
        let board = header.get("board").and_then(Value::as_str);
        let board_here = board == Some(self.named.board().as_str());
        let principal_here = header.get("principal").and_then(Value::as_u64) == Some(principal);
        if !board_here || !principal_here {
            let aside_chain = self.named.aside_of(board);
            drop(reader);
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
                // and its bytes count against the file's re-mark budget, save
                // the mark of its line `sent`, as the writer counts them.
                let spends = standing.get(&k).is_some_and(|was| !marks_sent(&was.reason, &line.reason));
                standing.insert(k, line);
                if spends {
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
        let held_bytes = lines.iter().map(HeldLine::held_bytes).sum();
        // The header's account is the file's own from here: what the join
        // opens the board's file under for a principal with no session now.
        let account = header.get("account").and_then(Value::as_str).map_or_else(|| disk.account.clone(), str::to_string);
        let disk = Disk { created: true, whole_bytes: reader.whole(), remark_bytes, torn, account, ..disk };
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
/// [`MAX_HELD_LINES`] — the next ordinal, the bytes its lines' frames and
/// anchors hold ([`MAX_HELD_BYTES`]'s count, each line's its
/// `HeldLine::held_bytes`), and the file the lines are copied to — `None`
/// where the store keeps them in memory alone (§3c.3) — beside the lines
/// still waiting for their first copy there ([`HeldQueue::waiting`]).
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
/// the bytes of its whole lines, the bytes of the re-mark lines it
/// holds that spend the re-mark budget ([`MAX_HELD_REMARK_BYTES`]'s count,
/// from its creation; a line's mark of `sent` spends none), and the queue's
/// lines still owed their first copy, where one was refused.
#[derive(Debug)]
struct Disk {
    path: PathBuf,
    /// The directory's name, which the header's `board` and `v` spell.
    named: Named,
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
    /// The queue's lines that wait for their first copy, where some do.
    ///
    /// Boxed: it stands only while a copy is refused, so a queue with none
    /// is no larger for it.
    waiting: Option<Box<Waiting>>,
}

/// One line entered in the queue: the ordinal it took, and why no copy stands.
///
/// The why is given where no copy of the line stands (§3c.3's
/// `store_unwritable`, which the `held` answer carries as `unwritable`): the
/// refusal of its copy — the device's, a full disk or a read-only volume, or
/// the writer's, a line past [`MAX_HELD_LINE_BYTES`] — or the refusal of the
/// copy of a line held before it, behind which it waits ([`Waiting`]). The
/// line stands in the queue either way.
#[derive(Debug)]
pub struct Entered {
    pub k: u64,
    pub unwritten: Option<io::Error>,
}

/// The lines of a queue that wait for their first copy (§3c.3; skep #813).
///
/// They are the line whose first copy was refused and every line held after
/// it: the standing lines from [`Waiting::first`] on, none of them on disk
/// and every line before them there, beside the refusal of the first. Made
/// where a line's first copy is refused, moved to the line a retry stops at,
/// and gone once no standing line waits ([`HeldQueue::retry`]).
#[derive(Debug)]
pub struct Waiting {
    /// The ordinal of the first line that waits: the one refused.
    first: u64,
    /// The refusal of the first line's copy: the device's or the writer's.
    error: io::Error,
}

impl Waiting {
    /// Returns the ordinal of the first line that waits: the one refused.
    pub fn first(&self) -> u64 {
        self.first
    }

    /// Returns the refusal of the first waiting line's copy.
    ///
    /// It is the refusal's kind and its words, which every waiting line
    /// answers as why no copy of it stands.
    pub fn refusal(&self) -> io::Error {
        io::Error::new(self.error.kind(), self.error.to_string())
    }
}

/// Why a line was not held, and is kept nowhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unheld {
    /// The queue is full, by its bytes, its lines or its ordinals.
    ///
    /// The queue's standing frames' and anchors' bytes, `held_bytes`, and
    /// the line's, its frame's `frame_bytes` and its anchors' `anchor_bytes`,
    /// would pass [`MAX_HELD_BYTES`] — or the queue's lines, `held_lines`,
    /// stand at [`MAX_HELD_LINES`] already, or past it as a reopened file
    /// can, or its next ordinal would pass [`MAX_ORDINAL`].
    Full { held_bytes: usize, frame_bytes: usize, anchor_bytes: usize, held_lines: usize },
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
    /// it (§3c.5): a line a resend settled was marked `sent` before its dial,
    /// so the read takes the landing it finds as the line's own.
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
    /// the file is new — behind every line still waiting for its first copy,
    /// which the retry copies first, in `k` order ([`HeldQueue::retry`]); a
    /// copy refused leaves the line waiting with them. `anchors` are the
    /// page's, kept with the line for the shift (skep #442), none where the
    /// burst carried none; their bytes spend the queue's budget beside the
    /// frame's. It answers the ordinal the line took and, where no copy of it
    /// stands, the refusal that keeps it off the disk — of its own copy, or of
    /// the copy of the line it waits behind — for the caller's answer to say
    /// (§3c.3).
    ///
    /// # Errors
    ///
    /// Returns [`Unheld`], checked in this order, the first that holds
    /// answering — its `doc` or `frame` one the reader refuses
    /// ([`Unheld::Unreadable`]), else its ordinal past [`MAX_ORDINAL`], the
    /// queue at [`MAX_HELD_LINES`] lines, or its frame and its anchors
    /// carrying the queue's past [`MAX_HELD_BYTES`] ([`Unheld::Full`]) — and
    /// the line kept nowhere: the writer holds no line the file's reader would
    /// halt on.
    pub fn hold(&mut self, doc: &str, id: Option<&str>, base: u64, frame: Value, anchors: Option<Anchors>, reason: Reason) -> Result<Entered, Unheld> {
        if document_address(doc).is_none() || !frame.is_object() {
            return Err(Unheld::Unreadable);
        }
        let frame_bytes = json_len(&frame);
        let anchor_bytes = anchors.as_ref().map_or(0, Anchors::bytes);
        let line_bytes = frame_bytes + anchor_bytes;
        if self.next_k > MAX_ORDINAL || self.lines.len() >= MAX_HELD_LINES || self.held_bytes.saturating_add(line_bytes) > MAX_HELD_BYTES {
            return Err(Unheld::Full { held_bytes: self.held_bytes, frame_bytes, anchor_bytes, held_lines: self.lines.len() });
        }
        let line = HeldLine { k: self.next_k, doc: doc.to_string(), id: id.map(str::to_string), base, frame, anchors, reason, time: now_ms() };
        let k = line.k;
        self.next_k += 1;
        self.held_bytes += line_bytes;
        self.lines.push(line);
        // The line's first copy is made behind every line still waiting for
        // its own.
        let from = self.waiting().map_or(k, Waiting::first);
        self.copy_run(from);
        Ok(Entered { k, unwritten: self.refusal_of(k) })
    }

    /// Returns the lines waiting for their first copy, where some do.
    ///
    /// They are the line whose copy was refused and every line held after it
    /// (§3c.3), none on disk; a queue in memory alone copies no line, and
    /// none waits there.
    pub fn waiting(&self) -> Option<&Waiting> {
        self.disk.as_ref()?.waiting.as_deref()
    }

    /// Copies the lines waiting for their first copy, in `k` order (§3c.3).
    ///
    /// It is the retry of a refused copy (skep #813): each waiting line is
    /// copied whole in its state now, one `write` then `sync_data` as a
    /// hold's copy is, and the first refused again stops it, the lines
    /// waiting on from that one under its refusal ([`Waiting`]). It runs
    /// before every copy the queue makes, and the shell runs it at every
    /// probe of the board, whatever the board's state. Where no line waits
    /// it writes nothing.
    pub fn retry(&mut self) {
        if let Some(from) = self.waiting().map(Waiting::first) {
            self.copy_run(from);
        }
    }

    /// Copies every standing line from ordinal `from` on, in `k` order.
    ///
    /// They are the first copies the lines are owed, each made whole in the
    /// line's state now. The first copy refused stops the run, which waits
    /// from that line on, its refusal kept; a run copied whole, or one whose
    /// lines have all left the queue, waits no more. A queue in memory alone
    /// copies nothing.
    fn copy_run(&mut self, from: u64) {
        let Some(disk) = self.disk.as_mut() else { return };
        let start = self.lines.partition_point(|l| l.k < from);
        for line in &self.lines[start..] {
            if let Err(error) = disk.write_line(&held_line_bytes(line)) {
                disk.waiting = Some(Box::new(Waiting { first: line.k, error }));
                return;
            }
        }
        disk.waiting = None;
    }

    /// Returns whether line `k`'s first copy stands on disk.
    ///
    /// It does where the queue has a file and the line waits for no copy.
    fn copied(&self, k: u64) -> bool {
        self.disk.as_ref().is_some_and(|d| d.waiting.as_ref().is_none_or(|w| k < w.first))
    }

    /// Returns why no copy of line `k` stands, where it waits for one.
    ///
    /// It is the refusal of the first waiting line's copy.
    fn refusal_of(&self, k: u64) -> Option<io::Error> {
        self.waiting().filter(|w| w.first <= k).map(Waiting::refusal)
    }

    /// Re-marks a standing line: its cause, refusal and `sent`.
    ///
    /// It appends a `held` line of its ordinal, which the reader takes in
    /// its place; no `done` is owed. A reason the line already has changes
    /// nothing and writes nothing. The queue takes the reason whatever the
    /// disk did. A line not standing is left alone. A line waiting for its
    /// first copy takes the reason in the queue alone, and the retry copies
    /// the line carrying it ([`HeldQueue::retry`]).
    ///
    /// # Errors
    ///
    /// Returns a copy refused — by the device, or past the file's
    /// [`MAX_HELD_REMARK_BYTES`], which a re-mark marking the line `sent`
    /// spends none of — for the caller to say (a reopen then reads the
    /// earlier reason).
    pub fn remark(&mut self, k: u64, reason: Reason) -> io::Result<()> {
        self.remark_raising(k, reason, None)
    }

    /// Re-marks a standing line and raises its `base` to `at`.
    ///
    /// It is the raise the person's `send` on a moved document writes
    /// (§3c.4; skep #757), beside the one a line kept on its document makes
    /// behind it ([`HeldQueue::done`]): `at` is the position the board's
    /// verdict on the document read through, the rows up to it the ones the
    /// act acknowledges, so the line's read for its own landing starts past
    /// them (§3c.5). The line takes `reason`, and its `base` is raised to
    /// `at` where `at` is past it — a base already past `at` stands, never
    /// lowered. It appends one `held` line of its ordinal carrying both,
    /// synced, which the reader takes in the earlier line's place as it takes
    /// a re-mark, so a reopen reads the raised base; a `done` kept below it
    /// later leaves it standing, in the queue and at a reopen alike, since
    /// either raise takes the greater. A reason and a base the line already
    /// carries change nothing and write nothing. The queue takes both
    /// whatever the disk did. A line not standing is left alone, and a line
    /// waiting for its first copy takes both in the queue alone, as a
    /// re-mark does ([`HeldQueue::remark`]).
    ///
    /// # Errors
    ///
    /// Returns a copy refused — by the device, or past the file's
    /// [`MAX_HELD_REMARK_BYTES`], which a raise spends as a re-mark does — for
    /// the caller to say (a reopen then reads the earlier reason and base).
    pub fn remark_raised(&mut self, k: u64, reason: Reason, at: u64) -> io::Result<()> {
        self.remark_raising(k, reason, Some(at))
    }

    /// Re-marks line `k` with `reason`, raising its `base` to `raise`.
    ///
    /// It is the body of [`HeldQueue::remark`], which raises nothing, and of
    /// [`HeldQueue::remark_raised`], whose raise takes the base where it is
    /// past it. The waiting lines are copied first, this one among them where
    /// it waits, its first copy carrying the re-mark; a line on disk then
    /// takes its re-mark's copy — one that marks the line `sent`
    /// (`marks_sent`) copied as a hold's line is, spending none of the
    /// re-mark budget, every other one within it ([`Disk::write_remark`]).
    fn remark_raising(&mut self, k: u64, reason: Reason, raise: Option<u64>) -> io::Result<()> {
        let Some(line) = self.lines.iter_mut().find(|l| l.k == k) else { return Ok(()) };
        let base = raise.map_or(line.base, |at| line.base.max(at));
        if line.reason == reason && line.base == base {
            return Ok(());
        }
        let marks = marks_sent(&line.reason, &reason);
        line.reason = reason;
        line.base = base;
        line.time = now_ms();
        let bytes = held_line_bytes(line);
        let copied = self.copied(k);
        self.retry();
        match self.disk.as_mut() {
            Some(d) if copied && marks => d.write_line(&bytes),
            Some(d) if copied => d.write_remark(&bytes),
            _ => Ok(()),
        }
    }

    /// Rewrites a standing line's frame: the shift's one act on a line
    /// (skep #442).
    ///
    /// It appends a `held` line of its ordinal carrying `frame` — the
    /// burst's positions moved through another writer's change, typed
    /// against the state they are true of — which the reader takes in the
    /// earlier line's place as it takes a re-mark; the reason, its `sent`,
    /// the `base`, the `id` and the anchors are kept. The copy is synced
    /// before this returns, so the shifted frame is on disk before it is
    /// dialed: a relaunch after the dial's answer is lost reads the landed
    /// test against the positions the shell sent, never the page's. A frame
    /// the line already carries changes nothing and writes nothing. The
    /// queue's bytes are recounted by the new frame, the line's anchors
    /// counted as they were — a shift changes digits, never what the queue's
    /// budget bounds, which is what a hold ADDS — and the queue takes the
    /// frame whatever the disk did. A line not standing is left alone. The
    /// waiting lines are copied first, this one among them where it waits —
    /// its first copy carrying the shifted frame and spending none of the
    /// re-mark budget — and a line on disk then takes the shift's copy.
    ///
    /// # Errors
    ///
    /// Returns a copy refused — by the device, or past the file's
    /// [`MAX_HELD_REMARK_BYTES`], which a shift spends a whole frame of as a
    /// re-mark does — for the caller to say: a reopen then reads the frame
    /// copied last, and the resend's read decides the line from there, the
    /// board judging the frame it sends as it judges every send.
    pub fn rewrite(&mut self, k: u64, frame: Value) -> io::Result<()> {
        let Some(line) = self.lines.iter_mut().find(|l| l.k == k) else { return Ok(()) };
        if line.frame == frame {
            return Ok(());
        }
        let was = line.held_bytes();
        line.frame = frame;
        line.time = now_ms();
        self.held_bytes = self.held_bytes.saturating_sub(was).saturating_add(line.held_bytes());
        let bytes = held_line_bytes(line);
        let copied = self.copied(k);
        self.retry();
        match self.disk.as_mut() {
            Some(d) if copied => d.write_remark(&bytes),
            _ => Ok(()),
        }
    }

    /// Resolves line `k` with a `done` line (§3c.2).
    ///
    /// The `done` is [`Done::Kept`] or [`Done::Dropped`]. The line leaves the
    /// queue whatever the disk did, and what the disk did is answered
    /// ([`Settled`]) for the caller to say. The waiting lines are copied
    /// first ([`HeldQueue::retry`]); a line itself waiting for its first copy
    /// has nothing on disk to resolve, and leaves with no `done` written.
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
        self.held_bytes = self.held_bytes.saturating_sub(line.held_bytes());
        // The lines from `index` on are those held after it, in `k` order.
        if let Done::Kept { at: Some(at) } = done {
            raise_bases(self.lines[index..].iter_mut(), &line.doc, at);
        }
        // A file never created, or a line waiting for its first copy, holds
        // nothing on disk to resolve.
        let copied = self.copied(k);
        self.retry();
        let unwritten = match self.disk.as_mut() {
            Some(d) if d.created && copied => d.append(&done_line_bytes(k, done)).err(),
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

    /// Returns the account the queue's file names in its header, where it has
    /// a file: the one the join opens the board's own file under.
    pub fn account(&self) -> Option<&str> {
        self.disk.as_ref().map(|d| d.account.as_str())
    }

    /// Returns the `board` the queue's file names in its header, where it has
    /// a file: a board's chain, or the origin a pending file carries.
    pub fn board(&self) -> Option<String> {
        self.disk.as_ref().map(|d| d.named.board())
    }

    /// Returns whether the queue's file is a pending directory's (the module
    /// doc), whose lines join the board's own file once `H.1` reads.
    pub fn is_pending(&self) -> bool {
        self.disk.as_ref().is_some_and(|d| matches!(d.named, Named::Pending { .. }))
    }

    /// Joins into this queue the standing lines of `from`, in `k` order.
    ///
    /// It is the module doc's join: `from` is the queue of a board's pending
    /// file, or one kept in memory alone, and this queue the board's own, its
    /// file opened under the chain `H.1` names. A line of `from` that a
    /// standing line here already carries — the same `doc`, `id` and frame,
    /// never the same ordinal, since the ordinals may have been renumbered —
    /// is not entered again, so a join cut between its writes and the pending
    /// file's removal re-runs whole at the next launch and doubles nothing.
    /// Where this queue holds no line and its next ordinal is at or below the
    /// first of `from`'s, each line KEEPS its ordinal and the next ordinal
    /// here is set past them, so a page holding the ordinals reads them
    /// unchanged; otherwise the lines are RENUMBERED from this queue's next
    /// ordinal in order, and the caller re-says `held` for their documents.
    /// Each line is copied to this queue's file and synced as it enters
    /// (persist-first), its `base`, frame, anchors, reason and `time` as
    /// `from` held them; the queue's bytes count each line's frame and
    /// anchors, and no budget refuses one — the join enters what stood, as a
    /// reopen reads a file whole, and the queue holds nothing more until it
    /// drains below its budgets. The lines of this queue waiting for their
    /// first copy are copied first ([`HeldQueue::retry`]), and no line of
    /// `from` enters ahead of one that still waits.
    ///
    /// # Errors
    ///
    /// Returns [`JoinRefused`], nothing entered and `from` untouched, where a
    /// line of this queue still waits for its first copy: at `from`'s first
    /// line, under the refusal the waiting line carries. Returns it too where
    /// a copy was refused — by the device, or for a line whose ordinal here
    /// would pass [`MAX_ORDINAL`] — and the join is UNDONE: every line it
    /// entered here is `done … dropped`, this queue standing as it stood, and
    /// `from` untouched, its file standing for the next launch's join.
    /// Nothing is lost, and nothing enters twice.
    pub fn join(&mut self, from: &HeldQueue) -> Result<Joined, JoinRefused> {
        self.retry();
        if let (Some(first), Some(waiting)) = (from.lines.first(), self.waiting()) {
            return Err(JoinRefused { k: first.k, error: waiting.refusal() });
        }
        let keep = self.lines.is_empty() && from.lines.first().is_some_and(|first| self.next_k <= first.k);
        let mut joined = Joined::default();
        for line in &from.lines {
            if self.lines.iter().any(|standing| standing.doc == line.doc && standing.id == line.id && standing.frame == line.frame) {
                joined.repeated += 1;
                continue;
            }
            let k = if keep { line.k } else { self.next_k };
            let refused = |error: io::Error| JoinRefused { k: line.k, error };
            if k > MAX_ORDINAL {
                self.undo(&joined);
                return Err(refused(io::Error::new(io::ErrorKind::InvalidInput, format!("the ordinal {k} is past the held store's {MAX_ORDINAL}"))));
            }
            let entered = HeldLine { k, ..line.clone() };
            if let Some(d) = self.disk.as_mut() {
                if let Err(e) = d.write_line(&held_line_bytes(&entered)) {
                    self.undo(&joined);
                    return Err(refused(e));
                }
            }
            // `k` is within MAX_ORDINAL, so its successor is a `u64`.
            self.next_k = k + 1;
            self.held_bytes = self.held_bytes.saturating_add(entered.held_bytes());
            self.lines.push(entered);
            joined.renumbered |= k != line.k;
            joined.entered.push((line.k, k));
        }
        Ok(joined)
    }

    /// Undoes a join that was refused mid-way: every line it entered is
    /// `done … dropped`, so this queue stands as it stood.
    fn undo(&mut self, joined: &Joined) {
        for &(_, k) in &joined.entered {
            // A `done` the device refuses leaves the line read as held at a
            // reopen, where the next join finds it standing and enters it no
            // second time; the refused copy is said by the join's caller.
            let _ = self.done(k, Done::Dropped);
        }
    }

    /// Removes the queue's file, where it has one: the pending file once its
    /// lines have joined the board's own (the module doc), after every one
    /// of them is on disk there.
    ///
    /// The queue is given up by its caller after; a file that went, or none
    /// that stood, is gone.
    ///
    /// # Errors
    ///
    /// Returns the unlink's I/O error other than a file not found, the file
    /// standing for the next launch's join.
    pub fn remove_file(&mut self) -> io::Result<()> {
        match self.disk.as_mut() {
            Some(d) => d.remove(),
            None => Ok(()),
        }
    }
}

/// What a join entered ([`HeldQueue::join`]), for the caller to re-key its
/// memory by and say.
#[derive(Debug, Default)]
pub struct Joined {
    /// Each line entered: the ordinal it had in the queue it came from, and
    /// the one it took here.
    pub entered: Vec<(u64, u64)>,
    /// The lines not entered again: a standing line here carries each.
    pub repeated: usize,
    /// Whether a line entered took another ordinal than it had.
    pub renumbered: bool,
}

/// Why a join was refused, and undone ([`HeldQueue::join`]).
#[derive(Debug)]
pub struct JoinRefused {
    /// The ordinal, in the queue joined from, of the line whose copy was
    /// refused — its first line, where a line of the queue joined into still
    /// waits for its copy.
    pub k: u64,
    /// The copy's refusal, or the waiting line's.
    pub error: io::Error,
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
    /// It copies every re-mark but a line's mark of `sent`, which is copied
    /// as a hold's line is (`HeldQueue::remark_raising`). Its bytes count as
    /// the copy is tried, so a device that takes a line and refuses its sync
    /// spends the budget all the same.
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
        let header = header_bytes(&self.named, self.principal, &self.account);
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
    /// crash) is named and not taken for a burst's first dial (§3c.6): R14's
    /// bound does not ask it, and the typing cadence would pay a synced append
    /// and tombstone churn. A held line's resend marks the line `sent` before
    /// it dials: its one write ahead of a dial, a re-mark of a line on disk.
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
/// hex, one `\n`: `v` 1 and the chain for a board's own file, `v` 2 and the
/// origin dialed for a pending one ([`Named`]).
fn header_bytes(named: &Named, principal: u64, account: &str) -> Vec<u8> {
    format!("{{\"type\":\"skep-held-bursts\",\"v\":{},\"board\":{},\"principal\":{principal},\"account\":{}}}\n", named.v(), json_str(&named.board()), json_str(account)).into_bytes()
}

/// Returns a `held` line's exact bytes (§3c.2).
///
/// Its members are `held, doc, id?, base, frame, anchors?, cause,
/// refusal?, sent, time`, in that order — `anchors` as
/// `{"before":<I-address or null>,"after":<I-address or null>}`, on a line
/// whose burst carried them alone, a span they name spelled before its
/// closing brace as `,"span":[{"start":<I-address>,"width":"<natural>"}]`,
/// one object per run.
fn held_line_bytes(l: &HeldLine) -> Vec<u8> {
    let mut s = format!("{{\"held\":{},\"doc\":{}", l.k, json_str(&l.doc));
    if let Some(id) = &l.id {
        let _ = write!(s, ",\"id\":{}", json_str(id));
    }
    let _ = write!(s, ",\"base\":{},\"frame\":{}", l.base, l.frame);
    if let Some(anchors) = &l.anchors {
        let anchor = |a: &Option<String>| a.as_deref().map_or_else(|| "null".to_string(), json_str);
        let _ = write!(s, ",\"anchors\":{{\"before\":{},\"after\":{}", anchor(&anchors.before), anchor(&anchors.after));
        if let Some(span) = &anchors.span {
            let runs: Vec<String> = span.iter().map(|run| format!("{{\"start\":{},\"width\":\"{}\"}}", json_str(&run.start()), run.width)).collect();
            let _ = write!(s, ",\"span\":[{}]", runs.join(","));
        }
        s.push('}');
    }
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
