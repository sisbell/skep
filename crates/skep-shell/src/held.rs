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
//! earlier line's place. Each line is written with its `\n` in one `write`,
//! with every copy owed before it where the file owes some (the retry,
//! below), and synced by `sync_data` before `op` answers `held` —
//! persist-first: the answer is a promise the disk already keeps. A reader
//! ignores a final line without `\n` within [`MAX_HELD_LINE_BYTES`] (a torn
//! last line is the burst a crash caught mid-append, R14's one).
//!
//! **A torn line is only ever the tail.** Every line is written where the
//! file's last whole line ends (`file::Appender`, trusting the count the
//! open made). A copy the device refuses — its write cut short, or its sync
//! refused — is cut back off the file, and a tail past the whole lines — a
//! crash's torn line, or a refused copy whose cut-back failed — is cut off
//! before the next line is written (`OnTail::Cut`), so no line is written
//! after bytes no reader reads, which would glue the two into one line the
//! reader halts on (P38); a refused copy's bytes whose cut-back failed are
//! cut by the retry too, before it writes ([`Disk::cut_tail`]), since their
//! whole lines would read as held lines to a fresh open. It is
//! the rule skep-blobs' `jsonl` log keeps. The
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
//! under the ordinal the hold hands it — the next of the principal's one
//! ordinal space (THE ORDINALS, below) — whatever the disk did. Every queue
//! names its file, the chain file or the pending one (below), and each line
//! is copied to it as it enters; a queue made before its file could be read
//! — the device refusing the store, §3c.3 — holds its lines owed to the
//! file until the hold reads it ([`HeldQueue::unopened`]), and a close
//! loses them. A line whose copy is
//! refused stands in the queue all the same, and so does a change to it, or
//! its leaving, whose copy is refused: the copy waits (below). A re-mark
//! that changes nothing is no line at all. A line kept at a position raises
//! to it the `base` of every line held after it on its document
//! ([`HeldQueue::done`]), in the queue as the `done` is written and again at
//! a reopen from that `done` line, so no line is rewritten to carry it
//! (§3c.2). The person's `send` on a moved document raises a line's `base`
//! to the position the board's verdict read through
//! ([`HeldQueue::remark_all`], §3c.4): a `held` line of its ordinal
//! carrying the raised base beside its new reason, which the reader takes in
//! the earlier line's place as it takes a re-mark. Neither raise lowers a
//! base: a base already past the position stands, and a later `done` kept
//! below a raised base leaves it. A line's frame is rewritten by one act
//! alone, the shift of a burst the board refused as typed against an older
//! state of its document ([`HeldQueue::rewrite`], skep #442): a `held` line
//! of its ordinal carrying the shifted frame, synced before the shifted
//! frame is dialed where the device takes it, so a relaunch reads the
//! positions the shell last sent, never the page's.
//!
//! **THE ORDINALS** (skep #856; the record `2026-11-06-held-store-investigation`
//! §1.4, re-said). One ordinal space per (board, principal) for the shell's
//! life: the hold's counter (`PrincipalHold::next_k`), which every queue the
//! principal's lines can be in — the file not yet read, the pending file,
//! the chain file — draws from, so an ordinal is assigned once and names
//! one line until that line leaves, never re-targeted once answered: the
//! ordinal a call holds across a dial, or the page holds off an `op` answer
//! or `held(session)`, names the line it held or none (I13). The one
//! renumbering left is of lines no one was ever answered: an earlier run's
//! file's, read after the first touch while it holds a line below the
//! counter.
//!
//! | act | the line's `k` | the counter | `k` outside the queue |
//! |---|---|---|---|
//! | the first touch | — | past the greatest ordinal in every file the shell can name then and does not read ([`HeldDir::greatest_ordinal`]) | — |
//! | hold ([`HeldQueue::hold`]) | the counter's | +1 | the `op` answer; the hold's clocks; a call's own local |
//! | re-mark, raise, shift | kept; a `held` line of the same `k` appended | — | — |
//! | `done`; the compaction | the line leaves; the file removed, the ordinals RUN ON | never wound back | the hold's memories dropped |
//! | the file read at the first touch ([`HeldDir::open_file`]) | the file's | past them | — |
//! | this run's lines moved to a file read later — the pending → chain change, or the file the store could not read at the first touch ([`Joining::ThisRun`]) | KEPT; an ordered insert | — | unchanged |
//! | an earlier run's pending file read beside the chain file ([`Joining::EarlierRun`]) | fresh, in the file's order | past them | none was answered |
//! | a file read after the first touch — the chain file at the change, or the file the store could not read before — holding a line below the counter ([`HeldQueue::renumber`]; skep #875) | its lines fresh, past every ordinal this run gave out | past them | none was answered |
//!
//! **The order** (I1): lines go out in `k` order per (board, principal),
//! each document's order within it, and nothing reaches the store ahead
//! of a line composed before it — save the *one* exception the owner
//! ruled: an earlier run's file read after the first touch — the board's,
//! which could not be named until `H.1` read, or the one the device refused
//! to read at the first touch — holding a line under an ordinal below the
//! hold's counter, which is past every ordinal this run gave out, standing
//! or settled, has its standing lines renumbered past it, so they walk after
//! this run's in their file's order; each still lands where its anchors
//! aim, or is held moved.
//!
//! **A refused copy waits, and every copy after it** (§3c.3; skep #813,
//! #821, #822, #861). The file owes the queue each line's first copy and,
//! for a line on disk, one copy of the changes made to it since — a re-mark,
//! a raise or a shift ([`HeldQueue::remark`], [`HeldQueue::remark_all`],
//! [`HeldQueue::rewrite`]) — or its `done` once it leaves the queue
//! ([`HeldQueue::done`], [`HeldQueue::done_all`]). Every such copy is
//! written by the retry ([`HeldQueue::retry`]), which the queue runs once at
//! the end of each act that owes copies — a hold, a join, a re-mark, a shift,
//! a `done`, and a RUN of re-marks or of `done`s, whose copies are all
//! entered owed before the one retry, so a run of any number of lines is one
//! copy — and the shell at every probe of the board, whatever the board's
//! state, so space freed while no one types is enough.
//! The retry writes the copies owed the lines on disk, then the first
//! copies, each in `k` order, as ONE copy — one `write`, then one
//! `sync_data`, the header its own copy before them where the file is new —
//! so a retry the device takes costs one sync whatever the queue holds;
//! only where the device refuses that copy does it write them one by one,
//! in the same order, so a device with room for some takes each that fits.
//! A copy the device refuses — its write cut short or its sync refused, its
//! bytes then cut back off the file — is OWED: kept in memory, its refusal
//! answered ([`Waiting`]), and written by a later retry; the retry stops at
//! the first copy the device refuses when written alone, every copy after it
//! waiting on: so no copy of a line is written while a copy owed a line
//! before it waits, the file never holds a line without every line standing
//! before it, and a reopen never resends a burst ahead of the one it was
//! composed after. A line on disk owes one copy at most, written in its
//! state then: a change made while it is owed rides it, and its `done` takes
//! the place of a re-mark owed before it, so no re-mark is written after its
//! line's `done`, where the reader would take it for a new line. A line
//! waiting for its first copy owes nothing more — a re-mark or a shift made
//! while it waits is carried in its first copy, spending none of the re-mark
//! budget, as the reader counts a line's first copy — and, leaving the
//! queue, writes no `done`, nothing of it standing on disk. A re-mark or a
//! shift the WRITER refuses before any I/O — past the file's
//! [`MAX_HELD_REMARK_BYTES`], or its line past [`MAX_HELD_LINE_BYTES`] — is
//! owed never, the file keeping the line's copy before it; a first copy the
//! writer refuses waits as one the device refused does, until its line
//! leaves, the copies before it written. A close loses every copy still
//! owed: a relaunch reads each line as the file last held it.
//!
//! **The pending directory** (§3c.1; skep #725, #857, #873). A board whose
//! head has not named its chain — the head record standing and not reading,
//! a claimed board serving none (the shell's `head_unreadable` hold, SP-14),
//! the board away or unclaimed at the first touch — has its lines go to
//! `held/pending/<hash>/principal-<n>.held`, `<hash>` the lowercase hex
//! SHA-256 of the origin dialed, as `Board::dialed` spells it
//! ([`HeldDir::pending`]), 64 hex as a chain's name is: the one directory
//! here named by an origin, the design's rule that no file here is bent for
//! it alone (§3c.1, §9 item 43). The directory is made and locked at every
//! board's first touch, whatever its head read answered, so a line goes to
//! disk before any head reads; it stands, empty but for its lock file, for
//! every board the shell touches. Its file is the chain file's in every
//! member save two — the header's `v` is 2 and its `board` the origin
//! dialed — and its lines are the chain file's lines, unchanged, each synced
//! before its answer as a chain file's is, so a close loses none and a
//! relaunch that dials the same origin finds them. Its reader is
//! [`HeldDir::open_file`] in the directory's own mode: it accepts `v` 2
//! alone — a `v` above it halts `Newer`, any other `v` the unknown-member
//! face — and a `board` equal to the origin dialed, another origin's file
//! set aside by the same non-overwriting rename under the hash of the origin
//! it names; the chain directory's reader is untouched, so a pending file
//! misplaced into a chain directory halts `Newer`. Once `H.1` reads and the
//! chain's directory is this shell's, the pending file's queue MOVES to the
//! chain file ([`HeldQueue::join`], `hold`'s pending → chain change): the
//! chain file is read, and every standing line of this run's enters its
//! queue under its own ordinal, a copy OWED, which the retry writes as ONE
//! copy — every line in one `write`, then one `sync_data` — one by one where
//! the device refuses it, each line that lands kept and the rest still owed;
//! a line still owed stands PARKED on the pending file meanwhile
//! ([`HeldQueue::parked`]), sent by no walk, since a send would leave the one
//! copy on disk reading it as never sent. Only once no copy is owed is the
//! pending file removed ([`HeldQueue::supersede`]): a crash before then
//! leaves both files, and the next launch's first touch reads the chain
//! file and the pending file beside it, the pending file's lines an earlier
//! run's. The join is an ORDERED INSERT: each line enters under its ordinal
//! and the queue is kept in `k` order whatever order the file holds the
//! lines in. This run's lines keep their ordinals ([`Joining::ThisRun`]) —
//! one whose ordinal a standing line already holds is that line, this run's
//! ordinals naming one line each, and is not entered again — and an earlier
//! run's file's lines take fresh ordinals from the principal's counter in
//! their file's order ([`Joining::EarlierRun`]), a line a standing chain
//! line already carries — by `doc`, `id` and frame, never by ordinal, since
//! that run's ordinals were its own — not entered again, each standing line
//! answering for one such line at most, so the lines a crash left are passed
//! over line for line and nothing is doubled, while two equal lines of the
//! file both enter. Where a copy's cut-back is refused too, the queue keeps
//! that its file holds the copy's bytes past its whole lines, and the retry
//! cuts them before it writes.
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
//! the lock (`file::remove`), every `done` it still owes going with it, since
//! no line of a file that is gone stands; a file is never rewritten in place,
//! its whole lines never touched — the writer's one cut takes only bytes past
//! the last of them. A removal the volume refuses — a permission, a read-only
//! volume — leaves the file standing, every line in it `done` or owed its
//! `done`, and the store appends on to it, its ordinals running on, answering
//! the failure for the shell to say once: a file the store thought gone would
//! refuse every later line `AlreadyExists` and keep every burst after it in
//! memory alone.
//!
//! **The store's budgets, on what a hold adds.** A line's anchors are bounded
//! at their one door ([`Anchors::of`]) by [`MAX_ANCHOR_BYTES`], the bridge's
//! argument and the held file's member alike, as the burst's door bounds its
//! frame by the board's frame cap. No line is held that would carry the
//! queue's standing frames and anchors past [`MAX_HELD_BYTES`], four frames
//! and one line's anchors at their bounds, or its lines past
//! [`MAX_HELD_LINES`] — a line past either refused and kept nowhere, and a
//! line whose `done` the file still owes counted in both until the `done`
//! lands or the file goes, since a reopen reads it standing. Both are
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
//! **The locks** `held/pending/<hash>/lock` and `held/<chain>/lock` (the key
//! store's `flock` idiom, copied from `search::directory::BoardDir::try_lock`
//! — the index directory's type is the index's) are each held by one shell
//! at a time, each for its holder's life once taken: the pending one at the
//! board's first touch, the board's own after it once a term has read, the
//! pending lock first (skep #828, #873). ONE SHELL PER DATA DIRECTORY
//! (§3c.3), each lock its holder's guard for the instant a second launch's
//! hand-off has not yet closed — a shell finding either held takes none,
//! opens no file under them and reads alone at the board, every write
//! refused at its door (`another_window`), and tries both again at every
//! probe and at every touch of the store — a session's open, a ceremony's
//! door (the hold's `Directory`).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use skep_client::Origin;
use skep_search::{aside_name, Chain};
use skep_util::file::{self, Appender, Fsync, LineReader, Next, OnTail};

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
/// board answering at once and no attest owed, its turns run back to back,
/// takes 1.7 s with every line on one document and 2.1 s with each on its
/// own, 9 s and 11 s unoptimized. At twice the lines, optimized, the reopen
/// takes 6.2 s and the walk 7.0 s and 8.7 s, past a few seconds. A drain
/// also pays each line's send, as a burst never held pays it but for the
/// copies: the attest a signed session composes, the board's write, and the
/// two copies its mark and its `done` sync to the device — about 13 ms a
/// line here, most of it the two copies.
pub const MAX_HELD_LINES: usize = 16384;

/// The ceiling the timing cells hold a reopen and a walk at the budgets to.
///
/// It is some seven times the slowest figure [`MAX_HELD_LINES`] states for
/// the build's profile — 2.1 s optimized, 11 s unoptimized — and loose on
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
/// base at the person's `send` ([`HeldQueue::remark_all`]) is a re-mark,
/// and spends it as one. Past it a re-mark is taken in the queue alone, its
/// copy refused by the writer and owed never ([`HeldQueue::remark`]): a
/// reopen reads the reason — and the frame and the base — copied last, and
/// the resend's read decides the line from there. A re-mark the device
/// refuses spends the budget once, as it is first tried; its retry, and
/// every change that rides it, spend none, since together they add one line
/// to the file (skep #821).
///
/// **The mark of `sent` spends none of it** (`marks_sent`). A resend marks
/// its line `sent` before it dials (§3c.2), and a drain of a full queue
/// marks every line in it, copying up to [`MAX_HELD_BYTES`] of re-mark lines,
/// past this budget; a mark refused would relaunch a line whose dial may have
/// landed as one never sent, which the resend sends again without the read
/// for its landing, and the person's text would land twice. A mark the device
/// refuses is owed, and the retry writes it past a spent budget too. A line
/// is marked once after its hold, and again only after a re-mark lowered its
/// `sent` and spent the budget, so the marks one file copies are bounded by
/// the lines it holds and by the budget.
const MAX_HELD_REMARK_BYTES: usize = MAX_HELD_LINE_BYTES;

/// The largest ordinal a line may carry: `2^53 − 1`.
///
/// It is the top of the range a JSON number carries exactly (AUTH-6.36's
/// clause) — the page names a line by its ordinal (`resolve`'s `held`), and
/// a JavaScript-backed page reads every number as a double. A file naming a
/// larger one is damaged, and a line whose ordinal would pass it is refused
/// ([`Unheld::Full`]). The ordinals are one space per (board, principal) for
/// the shell's life, never wound back — not at the compaction, which removes
/// the file and lets them run on (the module doc's THE ORDINALS) — and the
/// budget is not at risk: a shell holding a burst every 100 ms spends some
/// 3·10⁸ ordinals a year, so the space lasts some thirty million years.
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
    /// resend, which marks its line before it dials, synced — a mark the
    /// device refuses owed, and written by the retry (§3c.3) — so a crash or
    /// a refused write between the dial and its answer leaves the line read
    /// as one that may have landed, save a close while the mark itself is
    /// owed, which relaunches it as one never sent. It is `false` for a line
    /// held before any dial, or whose first dial reached no board or met its
    /// refusal — the death signal among them, a dead token's write committing
    /// nothing — until a resend of it is attempted. A re-mark keeps it,
    /// whatever that resend answers: one that never left, or one the board
    /// refused, says nothing of an earlier dial's write. A moved document's
    /// lines keep theirs, a line handed to the person keeps it too, and
    /// `resolve(send)` keeps every line's own, so a line that may have landed
    /// reads before it is sent again (§3c.5).
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
    /// The line's ordinal — the resend order, across the documents — one of
    /// the principal's one space for the shell's life, the hold's to hand
    /// out (the module doc's THE ORDINALS): assigned once, and never
    /// re-targeted once answered.
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
    /// ([`HeldQueue::remark_all`], §3c.4), so its read starts past the
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

    /// Returns whether the directory is a pending one (the module doc),
    /// named by the origin dialed.
    pub fn is_pending(&self) -> bool {
        matches!(self.named, Named::Pending { .. })
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
    /// writer left it. The lines are keyed by ORDINAL as the file is read in
    /// its order, and the file may hold a lower ordinal's lines after a
    /// higher one's (a join's ordered insert): a `held` line re-marks the
    /// line standing under its ordinal when it is read, wherever that line
    /// lies in the file, and is a new line where none stands; a `done` takes
    /// out the line standing under its ordinal and raises the standing lines
    /// of HIGHER ordinals on its document, never the lines written after it;
    /// and the re-mark budget counts a `held` line of a standing ordinal
    /// wherever it lies, so the queue read is the one the writer held, in
    /// `k` order, whatever the file's order. The whole lines' bytes are counted
    /// too, so the next line is written where the last of them ends, a torn
    /// tail cut off first; the open itself writes nothing, a tail it meets
    /// left for that cut and answered ([`HeldQueue::torn`]) for the shell
    /// to say once. `account` is the header's where this open writes one; a
    /// header read gives the queue the file's own.
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
        let disk = Disk { opened: true, ..self.disk(principal, account) };
        let fresh = |disk: Disk, aside: Option<PathBuf>| Opened::Live { queue: HeldQueue { disk, lines: Vec::new(), greatest_k: 0, held_bytes: 0 }, aside };
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
        Ok(Opened::Live { queue: HeldQueue { disk, lines, greatest_k: max_k, held_bytes }, aside: None })
    }

    /// Returns the disk of `principal`'s file here, as it stands before any
    /// read: not yet opened, nothing on it known.
    fn disk(&self, principal: u64, account: &str) -> Disk {
        Disk {
            path: self.path.join(Self::file_name(principal)),
            named: self.named.clone(),
            principal,
            account: account.to_string(),
            opened: false,
            refused: None,
            created: false,
            headless: false,
            torn: None,
            whole_bytes: 0,
            tail_left: false,
            remark_bytes: 0,
            owing: None,
            superseded: None,
        }
    }

    /// Returns the greatest ordinal the principal's file names, the file
    /// read and nothing written or moved.
    ///
    /// It is the hold's read, at a principal's first touch, of every file its
    /// lines can be in that the shell can name then — the pending file, and
    /// the chain file where `H.1` has read — so the principal's counter
    /// starts past every ordinal any of them names (the module doc's THE
    /// ORDINALS): the greatest `held` or `done` ordinal among the file's
    /// whole lines; 0 where no file stands or it holds no line, and 0 too
    /// where the file is not this directory's principal's own — no whole
    /// header line, or one of another `v`, another `board` or another
    /// `principal` — which the open alone halts or sets aside; a line that
    /// does not read ends the count at the lines before it, the file's halt
    /// the open's to find. A file under a lock another shell holds is read
    /// as it stands, a line it is writing a torn tail the count stops at.
    ///
    /// # Errors
    ///
    /// Returns the open's I/O error other than a file not found, or the
    /// read's.
    pub fn greatest_ordinal(&self, principal: u64) -> io::Result<u64> {
        let path = self.path.join(Self::file_name(principal));
        let Some(mut reader) = LineReader::open(&path, MAX_HELD_LINE_BYTES)? else { return Ok(0) };
        let Next::Line(bytes) = reader.next_line()? else { return Ok(0) };
        let Some(header) = object(bytes) else { return Ok(0) };
        let own = header.get("v").and_then(Value::as_u64) == Some(self.named.v())
            && header.get("type").and_then(Value::as_str) == Some("skep-held-bursts")
            && header.get("board").and_then(Value::as_str) == Some(self.named.board().as_str())
            && header.get("principal").and_then(Value::as_u64) == Some(principal);
        if !own {
            return Ok(0);
        }
        let mut greatest = 0;
        while let Next::Line(bytes) = reader.next_line()? {
            let named = object(bytes).and_then(|m| m.get("held").or_else(|| m.get("done")).and_then(ordinal));
            let Some(k) = named else { break };
            greatest = greatest.max(k);
        }
        Ok(greatest)
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
/// [`MAX_HELD_LINES`] — the greatest ordinal it has named, the bytes its
/// lines' frames and anchors hold ([`MAX_HELD_BYTES`]'s count, each line's
/// its `HeldLine::held_bytes`, a line whose `done` the file still owes among
/// them), and the file the lines are copied to — every queue names one, the
/// chain file or the pending one (the module doc), read before any copy is
/// written to it ([`HeldQueue::unopened`]) — beside the copies the file
/// still owes them ([`HeldQueue::waiting`]). The ordinals are the hold's to
/// hand out (the module doc's THE ORDINALS): the queue draws none of its
/// own.
#[derive(Debug)]
pub struct HeldQueue {
    disk: Disk,
    lines: Vec<HeldLine>,
    /// The greatest ordinal the queue has named: its file's, over every held
    /// and done line read, grown by each line held or entered since; 0 where
    /// it has named none.
    greatest_k: u64,
    held_bytes: usize,
}

/// The file a queue's lines are copied to.
///
/// It holds its path, the header's facts, whether the file has been read
/// yet — a queue made before its file could be read keeps every line owed
/// and writes nothing until the hold opens the file and takes them
/// ([`HeldQueue::unopened`]) — whether the header is on disk yet (created
/// lazily on the first append, under `create_new`, and again after a
/// compaction), whether a file with no whole header line stands for the
/// first append to cut and head, what the open found past the whole lines,
/// the bytes of its whole lines and whether a refused copy left bytes past
/// them, the bytes of the re-mark lines it holds that spend the re-mark
/// budget ([`MAX_HELD_REMARK_BYTES`]'s count, from its creation; a line's
/// mark of `sent` spends none), the copies it owes the queue's lines
/// (§3c.3) — those of the lines on disk, the lines still owed their first
/// copy, and where the retry last stopped — and the pending file whose
/// lines it took, removed once no copy is owed ([`Superseded`]).
#[derive(Debug)]
struct Disk {
    path: PathBuf,
    /// The directory's name, which the header's `board` and `v` spell.
    named: Named,
    principal: u64,
    account: String,
    /// Whether the file has been read.
    ///
    /// A queue over a file not yet read ([`HeldQueue::unopened`]) holds its
    /// lines in memory, every one owed its first copy, and writes nothing:
    /// the file may hold an earlier run's lines, which the hold reads and
    /// takes with this run's once the store can be made and locked
    /// ([`HeldQueue::join`]).
    opened: bool,
    /// The store's refusal that keeps the file unread, where one does.
    ///
    /// It is the device's refusal of the held directory or its lock, of the
    /// file's read, or of the renumbering the file's read owed, as the hold
    /// met it last ([`HeldQueue::refuse`]): what every line held meanwhile
    /// answers as why no copy of it stands ([`HeldQueue::waiting`]).
    refused: Option<io::Error>,
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
    /// every copy that lands. A file longer than this holds a tail — a
    /// crash's torn line, which no reader reads, or the bytes of a refused
    /// copy whose cut-back failed (`tail_left`) — which the next copy cuts
    /// off first ([`Disk::append`]).
    whole_bytes: u64,
    /// The file holds bytes past its whole lines that a refused copy left,
    /// its cut-back refused too.
    ///
    /// They are the copy's, whole lines among them that a fresh read would
    /// take for held lines: set as the cut-back is refused, and cleared by
    /// the next copy that lands, which cuts them first, or by the retry's
    /// cut before it writes ([`Disk::cut_tail`]).
    tail_left: bool,
    remark_bytes: usize,
    /// The copies the file owes the queue's lines, where it owes any.
    ///
    /// Boxed: it stands only while a copy is owed, so a queue owing none is
    /// no larger for it.
    owing: Option<Box<Owing>>,
    /// The pending file whose standing lines this file took, where one did.
    ///
    /// It is the file of the queue this one replaced at the pending → chain
    /// change, or an earlier run's pending file joined at the first touch
    /// (the module doc): removed by the retry once no copy is owed, so a
    /// crash before then leaves both files for the next launch's join, which
    /// doubles no line.
    superseded: Option<Superseded>,
}

/// A pending file whose lines a chain file took, standing until no copy is
/// owed ([`Disk::superseded`]).
#[derive(Debug)]
struct Superseded {
    path: PathBuf,
    /// The removal's refusal, where the retry met one: the file stands, and
    /// the next retry tries again.
    refused: Option<io::Error>,
    /// The lines the file holds standing, by the ordinal each has in this
    /// queue: each is PARKED while its copy here is owed
    /// ([`HeldQueue::parked`]), since a send of it would leave the one copy
    /// on disk reading it as never sent.
    standing: BTreeSet<u64>,
}

/// The copies a file owes its queue's lines, while it owes any (§3c.3;
/// skep #813, #821).
///
/// Made as a copy is entered for the retry (`HeldQueue::retry`), which
/// writes the copies owed the lines on disk and then the first copies, each
/// in `k` order, and gone once it has written every one.
#[derive(Debug, Default)]
struct Owing {
    /// The copies owed the lines on disk, by ordinal.
    ///
    /// Each is a line's state now — a re-mark, a raise or a shift whose copy
    /// the device refused, or one made while a copy owed before it waited —
    /// or, the line gone from the queue, its `done`: one per line at most.
    owed: BTreeMap<u64, Due>,
    /// The lines that wait for their first copy, by ordinal: each is in
    /// memory alone.
    ///
    /// They are the lines held since a copy was refused, and the lines a
    /// join enters ([`HeldQueue::join`]) — an earlier run's lines first read
    /// and renumbered past this run's stand on disk under higher ordinals
    /// than these, so the set, never a threshold, names them.
    first: BTreeSet<u64>,
    /// The copy the retry stopped at, and its refusal.
    stopped: Option<Waiting>,
}

/// One line entered in the queue: the ordinal it took, and why no copy stands.
///
/// The why is given where no copy of the line stands (§3c.3's
/// `store_unwritable`, which the `held` answer carries as `unwritable`, and
/// its kind's class as `unwritable_class`): the refusal of its copy — the
/// device's, a full disk or a read-only volume, or the writer's, a line past
/// [`MAX_HELD_LINE_BYTES`] — or the refusal of a copy owed before it — an
/// earlier line's first copy, its re-mark or its `done` — behind which it
/// waits ([`Waiting`]). The line stands in the queue either way.
#[derive(Debug)]
pub struct Entered {
    pub k: u64,
    pub unwritten: Option<io::Error>,
}

/// Where the copies the file owes its queue wait (§3c.3; skep #813, #821).
///
/// It names the copy the retry stopped at — the first the file owes, the
/// copies owed the lines on disk coming before the first copies, each in `k`
/// order — and the refusal it met; every copy owed after it waits behind it,
/// none written. Made where a copy is refused, moved to the one a retry stops
/// at, and gone once nothing is owed ([`HeldQueue::retry`]).
#[derive(Debug)]
pub struct Waiting {
    /// The ordinal of the line whose copy the retry stopped at.
    first: u64,
    /// Which of the line's copies it is.
    owed: Owed,
    /// The copy's refusal: the device's or the writer's.
    error: io::Error,
}

impl Waiting {
    /// Returns the ordinal of the line whose copy the retry stopped at.
    pub fn first(&self) -> u64 {
        self.first
    }

    /// Returns which of that line's copies the retry stopped at.
    pub fn owed(&self) -> Owed {
        self.owed
    }

    /// Returns the refusal of the copy the retry stopped at.
    ///
    /// It is the refusal's kind and its words, which every line waiting for
    /// its first copy answers as why no copy of it stands — the words as
    /// `unwritable`, and the kind's class as `unwritable_class`.
    pub fn refusal(&self) -> io::Error {
        io::Error::new(self.error.kind(), self.error.to_string())
    }
}

/// Which of a line's copies the file owes ([`Waiting::owed`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owed {
    /// Its first copy: nothing of the line stands on disk.
    Line,
    /// A copy of its state now: a re-mark, a raise or a shift made since the
    /// copy the file holds.
    Mark,
    /// Its `done`: the line has left the queue, and the file holds it
    /// standing.
    Done,
}

/// A copy the file owes a line on disk ([`Owing::owed`]).
#[derive(Debug, Clone, Copy)]
enum Due {
    /// The line's state now, written whole.
    Mark,
    /// The line's `done`, the line gone from the queue.
    ///
    /// `bytes` are its frame's and its anchors', which the queue's budget
    /// counts until the `done` lands ([`MAX_HELD_BYTES`]), as a reopen reads
    /// the line standing until then.
    Done { done: Done, bytes: usize },
}

impl Due {
    /// Returns which copy it is, as [`Waiting::owed`] names it.
    fn owed(self) -> Owed {
        match self {
            Due::Mark => Owed::Mark,
            Due::Done { .. } => Owed::Done,
        }
    }
}

/// One copy the retry writes ([`HeldQueue::retry`]).
///
/// It is the ordinal of the line it is owed, which of the line's copies it
/// is, and its exact bytes — one line and its `\n` — so a refusal of it
/// waits under the copy it names.
#[derive(Debug)]
struct OwedCopy {
    k: u64,
    owed: Owed,
    bytes: Vec<u8>,
}

impl OwedCopy {
    /// Returns the wait a refusal of this copy leaves, from this copy on.
    fn refused(&self, error: io::Error) -> Waiting {
        Waiting { first: self.k, owed: self.owed, error }
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
    /// can, or the ordinal the line would take passes [`MAX_ORDINAL`]. A
    /// line whose `done` the file still owes is counted in both, the file
    /// holding it standing.
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

/// What settling lines did beyond the queue, for the caller to say.
///
/// Each line settled — one by [`HeldQueue::done`], or a run by
/// [`HeldQueue::done_all`] — has left the queue whatever the disk did: a
/// `done` the device refuses is owed, and waits as every copy owed does
/// ([`HeldQueue::waiting`]).
#[derive(Debug, Default)]
pub struct Settled {
    /// The queue emptied and its file could not be removed.
    ///
    /// The file stands, every line in it `done` or owed its `done`, and the
    /// store appends on to it, its ordinals running on; named by its path.
    pub unremoved: Option<(PathBuf, io::Error)>,
}

impl HeldQueue {
    /// Returns a queue over `principal`'s file in `dir`, the file not yet
    /// read (§3c.3).
    ///
    /// It is the queue of a principal whose store the device has refused —
    /// the held directory or its lock not to be made, or the file's read
    /// refused — so the file cannot be opened yet: its lines enter and leave
    /// as a file's do, every one owed its first copy under the refusal the
    /// hold hands it ([`HeldQueue::refuse`]), and no copy is written, since
    /// the file may hold an earlier run's lines no write may land behind —
    /// a close loses them. The hold opens the file once the store is made
    /// and locked, and takes these lines into the file's queue
    /// ([`HeldQueue::join`]). `account` is the header's, where the file
    /// comes to be written.
    pub fn unopened(dir: &HeldDir, principal: u64, account: &str) -> HeldQueue {
        HeldQueue { disk: dir.disk(principal, account), lines: Vec::new(), greatest_k: 0, held_bytes: 0 }
    }

    /// Gives an unopened queue the store's refusal that keeps its file
    /// unread: the device's, of the directory, its lock or the file's read.
    ///
    /// Every line held meanwhile answers it as why no copy of it stands
    /// ([`HeldQueue::waiting`]), in its kind and its words.
    ///
    /// **Precondition.** The queue's file is not yet read
    /// ([`HeldQueue::unopened`]): an opened queue's refusals are the
    /// retry's own, kept as it meets them.
    pub fn refuse(&mut self, refused: io::Error) {
        debug_assert!(!self.disk.opened, "PRECONDITION of `HeldQueue::refuse`: the queue's file is not yet read");
        self.disk.refused = Some(refused);
        self.retry();
    }

    /// Returns whether the queue's file has been read.
    ///
    /// It has not where the queue was made before its store could be
    /// ([`HeldQueue::unopened`]): its lines are in memory alone.
    pub fn is_opened(&self) -> bool {
        self.disk.opened
    }

    /// Returns the path of the queue's file, read or not.
    pub fn path(&self) -> &Path {
        &self.disk.path
    }

    /// Returns the un-done `held` lines, in `k` order.
    pub fn lines(&self) -> &[HeldLine] {
        &self.lines
    }

    /// Returns the greatest ordinal the queue has named: its file's, over
    /// every held and done line, grown by each line held or entered since —
    /// what the hold's counter starts past as it takes the queue (the module
    /// doc's THE ORDINALS); 0 where it has named none.
    pub fn greatest_k(&self) -> u64 {
        self.greatest_k
    }

    /// Holds a line under the ordinal past every one the queue has named.
    ///
    /// It is the store's cells' stand-in for the hold's counter
    /// (`PrincipalHold::next_k`), which the shell draws every ordinal from:
    /// a lone queue's counter is one past its greatest.
    #[cfg(test)]
    pub(crate) fn hold_next(&mut self, doc: &str, id: Option<&str>, base: u64, frame: Value, anchors: Option<Anchors>, reason: Reason) -> Result<Entered, Unheld> {
        self.hold(self.greatest_k + 1, doc, id, base, frame, anchors, reason)
    }

    /// Returns whether the queue's file is on disk, its header written.
    #[cfg(test)]
    fn on_disk(&self) -> bool {
        self.disk.path.exists()
    }

    /// Returns what the open found past the file's whole lines, if anything.
    ///
    /// It is a crash's tail — no whole header line, or a torn last line —
    /// read as no line and cut off by the next line written: the open's
    /// own fact, for the shell to say once. A queue whose file is not yet
    /// read, or read whole, has none.
    pub fn torn(&self) -> Option<Torn> {
        self.disk.torn
    }

    /// Holds a line: enters it in the queue under the ordinal `k`.
    ///
    /// `k` is the principal's next ordinal, the hold's counter's (the module
    /// doc's THE ORDINALS): the line's for the shell's life. Where the queue
    /// has a file, the line is copied to it by the retry,
    /// behind every copy the file still owes, in `k` order — the copies and
    /// the line one `write` then one `sync_data` (persist-first), the header
    /// written once first where the file is new ([`HeldQueue::retry`]); a
    /// copy refused, its own or one before it, leaves the line waiting for its
    /// first copy. `anchors` are the page's, kept with the line for the shift
    /// (skep #442), none where the burst carried none; their bytes spend the
    /// queue's budget beside the frame's. It answers the ordinal the line took
    /// and, where no copy of it stands, the refusal that keeps it off the disk
    /// — of its own copy, or of the copy owed before it that it waits behind —
    /// for the caller's answer to say (§3c.3).
    ///
    /// **Precondition.** `k` is past every ordinal a standing line holds: the
    /// counter never hands out an ordinal twice, and starts past every one
    /// the file names, so a line held is held after every line standing.
    ///
    /// # Errors
    ///
    /// Returns [`Unheld`], checked in this order, the first that holds
    /// answering — its `doc` or `frame` one the reader refuses
    /// ([`Unheld::Unreadable`]), else `k` past [`MAX_ORDINAL`], the
    /// queue at [`MAX_HELD_LINES`] lines, or its frame and its anchors
    /// carrying the queue's past [`MAX_HELD_BYTES`] ([`Unheld::Full`]), a line
    /// whose `done` the file still owes counted in both — and the line kept
    /// nowhere: the writer holds no line the file's reader would halt on.
    ///
    /// # Panics
    ///
    /// Panics where `k` is not past every ordinal a standing line holds (the
    /// precondition, the caller's).
    #[allow(clippy::too_many_arguments)]
    pub fn hold(&mut self, k: u64, doc: &str, id: Option<&str>, base: u64, frame: Value, anchors: Option<Anchors>, reason: Reason) -> Result<Entered, Unheld> {
        assert!(self.lines.last().is_none_or(|last| last.k < k), "PRECONDITION of `HeldQueue::hold`: the ordinal {k} is past every one a standing line holds");
        if document_address(doc).is_none() || !frame.is_object() {
            return Err(Unheld::Unreadable);
        }
        let frame_bytes = json_len(&frame);
        let anchor_bytes = anchors.as_ref().map_or(0, Anchors::bytes);
        let line_bytes = frame_bytes + anchor_bytes;
        let held_lines = self.held_lines();
        if k > MAX_ORDINAL || held_lines >= MAX_HELD_LINES || self.held_bytes.saturating_add(line_bytes) > MAX_HELD_BYTES {
            return Err(Unheld::Full { held_bytes: self.held_bytes, frame_bytes, anchor_bytes, held_lines });
        }
        let line = HeldLine { k, doc: doc.to_string(), id: id.map(str::to_string), base, frame, anchors, reason, time: now_ms() };
        self.greatest_k = self.greatest_k.max(k);
        self.held_bytes += line_bytes;
        self.lines.push(line);
        // The line's first copy is owed behind every copy owed before it.
        self.disk.owing.get_or_insert_with(Box::default).first.insert(k);
        self.retry();
        Ok(Entered { k, unwritten: self.refusal_of(k) })
    }

    /// Returns the lines the queue's budget counts ([`MAX_HELD_LINES`]).
    ///
    /// They are its standing lines and those whose `done` the file still
    /// owes, which a reopen reads standing.
    fn held_lines(&self) -> usize {
        let owing = self.disk.owing.as_deref();
        self.lines.len() + owing.map_or(0, |o| o.owed.values().filter(|due| matches!(due, Due::Done { .. })).count())
    }

    /// Returns where the copies the file owes wait, where some do.
    ///
    /// They are the copies owed the lines on disk and the first copies of the
    /// lines that wait for theirs (§3c.3), none of them on disk — every line
    /// of a queue whose file is not yet read among them, under the store's
    /// refusal ([`HeldQueue::refuse`]).
    pub fn waiting(&self) -> Option<&Waiting> {
        self.disk.owing.as_ref()?.stopped.as_ref()
    }

    /// Writes the copies the file owes, in `k` order, as one copy.
    ///
    /// It is the retry (§3c.3; skep #813, #821, #822), which makes every copy
    /// the queue makes but the renumbering's ([`HeldQueue::renumber`]): first
    /// the copies owed the lines on disk, each line's state now or its `done`,
    /// then the first copies of the lines that wait, each made whole in its
    /// state now, spending none of the re-mark budget, which a re-mark spent
    /// as it was first tried. They are ONE copy — every line of them in one
    /// `write`, then one `sync_data`, the header its own copy before them
    /// where the file is new ([`Disk::write_copies`]) — so a retry the device
    /// takes costs one sync whatever the queue holds; only where the device
    /// refuses that copy are they copied one by one, in the same order, so a
    /// device with room for some takes each that fits. The first copy refused
    /// stops it — by the writer, a first copy past [`MAX_HELD_LINE_BYTES`] or
    /// a line owed a re-mark that a raise of its base has carried past it
    /// since, the copies before it written all the same; or by the device,
    /// written alone — and every copy from that one on waits under its
    /// refusal ([`Waiting`]); a `done` that lands gives its line's bytes back
    /// to the queue's budget. The queue runs it once at the end of each act
    /// that owes copies — a run of re-marks or of `done`s once for the whole
    /// run, every copy of it entered owed first ([`HeldQueue::remark_all`],
    /// [`HeldQueue::done_all`]; skep #861) — and the shell runs it at every
    /// probe of the board, whatever the board's state. It is the one act
    /// that moves bytes from memory to disk: before it writes, it cuts
    /// the bytes a refused copy left past the file's whole lines where its
    /// cut-back was refused too ([`Disk::cut_tail`]), so the file holds what
    /// the queue knows of it; once nothing is owed, it removes the pending
    /// file whose lines this file took ([`HeldQueue::supersede`]). A queue
    /// whose file is not yet read ([`HeldQueue::unopened`]) writes nothing
    /// — every line of it waits under the store's refusal — since the file
    /// may hold lines no write may land behind.
    pub fn retry(&mut self) {
        let disk = &mut self.disk;
        if !disk.opened {
            // Every line waits under the store's refusal, where one is known.
            if let (Some(owing), Some(refused)) = (disk.owing.as_mut(), &disk.refused) {
                owing.stopped = owing.first.first().map(|&first| Waiting { first, owed: Owed::Line, error: io::Error::new(refused.kind(), refused.to_string()) });
            }
            return;
        }
        disk.cut_tail();
        let Some(mut owing) = disk.owing.take() else {
            disk.remove_superseded();
            return;
        };
        // The copies in the order they are written, up to the first the
        // writer refuses, which stops the retry there.
        let on_disk = owing.owed.iter().filter_map(|(&k, &due)| {
            let bytes = match due {
                // A line no longer standing owes no copy of its state.
                Due::Mark => held_line_bytes(&self.lines[self.lines.binary_search_by_key(&k, |l| l.k).ok()?]),
                Due::Done { done, .. } => done_line_bytes(k, done),
            };
            Some(OwedCopy { k, owed: due.owed(), bytes })
        });
        let first = self.lines.iter().filter(|line| owing.first.contains(&line.k)).map(|line| OwedCopy { k: line.k, owed: Owed::Line, bytes: held_line_bytes(line) });
        let mut copies = Vec::new();
        let mut stop = None;
        for copy in on_disk.chain(first) {
            if let Some(refused) = past_the_line_bound(&copy.bytes) {
                stop = Some(copy.refused(refused));
                break;
            }
            copies.push(copy);
        }
        let landed = match disk.write_copies(&copies) {
            Ok(()) => copies.len(),
            Err((n, error)) => {
                stop = Some(copies[n].refused(error));
                n
            }
        };
        for copy in &copies[..landed] {
            if copy.owed == Owed::Line {
                owing.first.remove(&copy.k);
            } else if let Some(Due::Done { bytes, .. }) = owing.owed.remove(&copy.k) {
                self.held_bytes = self.held_bytes.saturating_sub(bytes);
            }
        }
        match stop {
            Some(waiting) => {
                owing.stopped = Some(waiting);
                disk.owing = Some(owing);
            }
            // Every copy landed: nothing is owed, and the pending file this
            // file took its lines from goes.
            None => disk.remove_superseded(),
        }
    }

    /// Returns whether line `k`'s first copy stands on disk.
    ///
    /// It does where the file is read and the line waits for no first copy
    /// ([`Disk::holds`]).
    fn copied(&self, k: u64) -> bool {
        self.disk.holds(k)
    }

    /// Returns why no copy of line `k` stands, where it waits for one.
    ///
    /// It is the refusal of the copy the retry stopped at: the line's own, or
    /// one owed before it.
    fn refusal_of(&self, k: u64) -> Option<io::Error> {
        self.waiting().filter(|_| !self.copied(k)).map(Waiting::refusal)
    }

    /// Re-marks a standing line: its cause, refusal and `sent`.
    ///
    /// It appends a `held` line of its ordinal, which the reader takes in
    /// its place; no `done` is owed. A reason the line already has changes
    /// nothing and writes nothing. The queue takes the reason whatever the
    /// disk did, and a copy the device refuses is owed, written by the retry
    /// in its place in `k` order ([`HeldQueue::retry`]) — as is the copy of a
    /// line on disk re-marked while a copy owed before it waits. A line not
    /// standing is left alone. A line waiting for its first copy takes the
    /// reason in the queue alone, and the retry copies the line carrying it.
    /// A run of re-marks is [`HeldQueue::remark_all`]'s, one copy for the run.
    ///
    /// # Errors
    ///
    /// Returns the writer's refusal of the copy, owed never — past the file's
    /// [`MAX_HELD_REMARK_BYTES`], of which a re-mark marking the line `sent`,
    /// or riding a copy owed already, spends none; or a line past
    /// [`MAX_HELD_LINE_BYTES`] — for the caller to say (a reopen then reads
    /// the earlier reason).
    pub fn remark(&mut self, k: u64, reason: Reason) -> io::Result<()> {
        let Some((index, spends)) = self.restate(k, reason, None) else { return Ok(()) };
        self.owe(index, spends)
    }

    /// Re-marks a run of standing lines as one copy.
    ///
    /// It is the run's form of a re-mark (§3c.3; skep #861), each `base`
    /// raised to `raise` where it names one. Each of `marks` is a line's
    /// ordinal and its new reason, taken as [`HeldQueue::remark`] takes one:
    /// a line not standing left alone, a reason and a base the line carries
    /// already changing nothing, a line waiting for its first copy taking
    /// both in the queue alone, and the queue taking each whatever the disk
    /// did. Every copy the run owes is entered before the one retry
    /// ([`HeldQueue::retry`]), so the run's copies go in one `write` and one
    /// `sync_data` however many lines it re-marks, and the file holds after
    /// it what a re-mark of each line in turn leaves; a copy the device
    /// refuses is owed, as a lone re-mark's is. A run that changes nothing
    /// writes nothing.
    ///
    /// **The raise** (§3c.4; skep #757). Where `raise` names a position, each
    /// line's `base` is raised to it where it is past the base — a base
    /// already past it stands, never lowered. It is the raise the person's
    /// `send` on a moved document writes, beside the one a line kept on its
    /// document makes behind it ([`HeldQueue::done`]): the position the
    /// board's verdict on the document read through, the rows up to it the
    /// ones the act acknowledges, so each line's read for its own landing
    /// starts past them (§3c.5). The raised base rides the line's `held` copy
    /// beside its new reason, which the reader takes in the earlier line's
    /// place as it takes a re-mark, so a reopen reads it; a `done` kept below
    /// it later leaves it standing, in the queue and at a reopen alike, since
    /// either raise takes the greater.
    ///
    /// It answers each copy the writer refused before any I/O, beside its
    /// line's ordinal, in the order of `marks`, each owed never — past the
    /// file's [`MAX_HELD_REMARK_BYTES`], which a raise spends as a re-mark
    /// does and of which a re-mark marking its line `sent`, or riding a copy
    /// owed already, spends none; or a line past [`MAX_HELD_LINE_BYTES`] —
    /// for the caller to say: a reopen reads each such line's earlier copy.
    pub fn remark_all(&mut self, marks: impl IntoIterator<Item = (u64, Reason)>, raise: Option<u64>) -> Vec<(u64, io::Error)> {
        let mut changed = false;
        let mut refused = Vec::new();
        for (k, reason) in marks {
            let Some((index, spends)) = self.restate(k, reason, raise) else { continue };
            changed = true;
            if let Err(e) = self.owe_copy(index, spends) {
                refused.push((k, e));
            }
        }
        if changed {
            self.retry();
        }
        refused
    }

    /// Takes a re-mark's change into line `k`, in the queue alone.
    ///
    /// It is the change every re-mark makes ([`HeldQueue::remark`],
    /// [`HeldQueue::remark_all`]): the line takes `reason`, its `base` is
    /// raised to `raise` where that is past it, and its `time` is the
    /// change's. It answers the line's index and whether its copy spends the
    /// re-mark budget — one that marks the line `sent` (`marks_sent`) spends
    /// none of it, and every other one is within it — and none where no line
    /// of `k` stands or the line carries the reason and the base already.
    fn restate(&mut self, k: u64, reason: Reason, raise: Option<u64>) -> Option<(usize, bool)> {
        let index = self.lines.iter().position(|l| l.k == k)?;
        let line = &mut self.lines[index];
        let base = raise.map_or(line.base, |at| line.base.max(at));
        if line.reason == reason && line.base == base {
            return None;
        }
        let spends = !marks_sent(&line.reason, &reason);
        line.reason = reason;
        line.base = base;
        line.time = now_ms();
        Some((index, spends))
    }

    /// Owes the copy of line `index`'s state now, and runs the retry.
    ///
    /// It is one change's copy ([`HeldQueue::owe_copy`]), which the retry
    /// writes in its place in `k` order, behind every copy owed before it
    /// ([`HeldQueue::retry`]).
    ///
    /// # Errors
    ///
    /// Returns the writer's refusal, the copy owed never.
    fn owe(&mut self, index: usize, spends: bool) -> io::Result<()> {
        let owed = self.owe_copy(index, spends);
        self.retry();
        owed
    }

    /// Owes the copy of line `index`'s state now, for the next retry.
    ///
    /// A line waiting for its first copy owes nothing more: its first copy
    /// carries its state. A line on disk owes one copy ([`Disk::owe_mark`]),
    /// which the writer refuses first — its line past [`MAX_HELD_LINE_BYTES`],
    /// or a copy that `spends`, riding no copy owed already, past
    /// [`MAX_HELD_REMARK_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns the writer's refusal, the copy owed never.
    fn owe_copy(&mut self, index: usize, spends: bool) -> io::Result<()> {
        let k = self.lines[index].k;
        if self.disk.holds(k) {
            self.disk.owe_mark(k, &held_line_bytes(&self.lines[index]), spends)
        } else {
            Ok(())
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
    /// before this returns where the device takes it, so the shifted frame is
    /// on disk before it is dialed: a relaunch after the dial's answer is lost
    /// reads the landed test against the positions the shell sent, never the
    /// page's. A copy the device refuses is owed, as a re-mark's is, and a
    /// close before the retry writes it relaunches the frame copied last. A
    /// frame the line already carries changes nothing and writes nothing. The
    /// queue's bytes are recounted by the new frame, the line's anchors
    /// counted as they were — a shift changes digits, never what the queue's
    /// budget bounds, which is what a hold ADDS — and the queue takes the
    /// frame whatever the disk did. A line not standing is left alone. A line
    /// waiting for its first copy takes the frame in the queue alone, its
    /// first copy carrying it and spending none of the re-mark budget.
    ///
    /// # Errors
    ///
    /// Returns the writer's refusal of the copy, owed never — past the file's
    /// [`MAX_HELD_REMARK_BYTES`], which a shift spends a whole frame of as a
    /// re-mark does, or a line past [`MAX_HELD_LINE_BYTES`] — for the caller
    /// to say: a reopen then reads the frame copied last, and the resend's
    /// read decides the line from there, the board judging the frame it sends
    /// as it judges every send.
    pub fn rewrite(&mut self, k: u64, frame: Value) -> io::Result<()> {
        let Some(index) = self.lines.iter().position(|l| l.k == k) else { return Ok(()) };
        let line = &mut self.lines[index];
        if line.frame == frame {
            return Ok(());
        }
        let was = line.held_bytes();
        line.frame = frame;
        line.time = now_ms();
        self.held_bytes = self.held_bytes.saturating_sub(was).saturating_add(line.held_bytes());
        self.owe(index, true)
    }

    /// Resolves line `k` with a `done` line (§3c.2).
    ///
    /// The `done` is [`Done::Kept`] or [`Done::Dropped`]. The line leaves the
    /// queue whatever the disk did. A line on disk owes its `done`, which
    /// takes the place of a re-mark owed it and which the retry writes in its
    /// place in `k` order ([`HeldQueue::retry`]); a `done` the device refuses
    /// stays owed, its line counted in the queue's budgets until it lands
    /// ([`Unheld::Full`]). A line itself waiting for its first copy has
    /// nothing on disk to resolve, and leaves with no `done` owed. A run of
    /// `done`s is [`HeldQueue::done_all`]'s, one copy for the run.
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
    /// (§3c.3), every `done` it still owes going with it; the ordinals run
    /// on, the hold's counter never wound back (the module doc's THE
    /// ORDINALS). A removal the volume refuses leaves the file standing,
    /// every line in it `done` or owed its `done`, and the store appends on to
    /// it — the ordinals running on past the file's either way, so no line is
    /// written under an ordinal the file names standing — answering the
    /// failure beside the settle.
    ///
    /// # Errors
    ///
    /// Returns [`DoneError::NoSuchLine`] for an ordinal with no `held` line:
    /// the `done` is refused.
    pub fn done(&mut self, k: u64, done: Done) -> Result<Settled, DoneError> {
        self.leave(k, done)?;
        Ok(self.settle())
    }

    /// Resolves a run of lines with `done` lines, as one copy.
    ///
    /// It is the run's form of a `done` (§3c.2; skep #861). Each line of `ks`
    /// leaves the queue in the order given, as [`HeldQueue::done`] takes one
    /// — a line kept at a position raising the bases behind it on its
    /// document, a line on disk owing its `done` and a line waiting for its
    /// first copy leaving with none owed — and an ordinal with no `held` line
    /// is passed over. Every `done` the run owes is entered before the one
    /// retry ([`HeldQueue::retry`]), so the run's `done`s go in one `write`
    /// and one `sync_data` however many lines it settles, and the file holds
    /// after it what a `done` of each line in turn leaves; a `done` the device
    /// refuses is owed, as a lone `done`'s is. Where the run empties the
    /// queue, its `done`s are written before the compaction removes the file,
    /// a removal the volume refuses answered beside the settle. A run that
    /// settles no line writes nothing.
    pub fn done_all(&mut self, ks: &[u64], done: Done) -> Settled {
        let mut left = false;
        for &k in ks {
            left |= self.leave(k, done).is_ok();
        }
        if left {
            self.settle()
        } else {
            Settled::default()
        }
    }

    /// Takes line `k` out of the queue, owing its `done` where it is on disk.
    ///
    /// It is the change every `done` makes ([`HeldQueue::done`],
    /// [`HeldQueue::done_all`]), before the retry that writes it.
    ///
    /// # Errors
    ///
    /// Returns [`DoneError::NoSuchLine`] for an ordinal with no `held` line,
    /// the queue as it stood.
    fn leave(&mut self, k: u64, done: Done) -> Result<(), DoneError> {
        let Some(index) = self.lines.iter().position(|l| l.k == k) else { return Err(DoneError::NoSuchLine) };
        let line = self.lines.remove(index);
        // The lines from `index` on are those held after it, in `k` order.
        if let Done::Kept { at: Some(at) } = done {
            raise_bases(self.lines[index..].iter_mut(), &line.doc, at);
        }
        // A file never created, or a line waiting for its first copy, holds
        // nothing on disk to resolve; a line on disk owes its `done`, counted
        // until it lands.
        let bytes = line.held_bytes();
        if self.disk.created && self.disk.holds(k) {
            self.disk.owing.get_or_insert_with(Box::default).owed.insert(k, Due::Done { done, bytes });
        } else {
            self.held_bytes = self.held_bytes.saturating_sub(bytes);
            if let Some(owing) = self.disk.owing.as_mut() {
                owing.first.remove(&k);
            }
        }
        Ok(())
    }

    /// Writes the `done`s owed, and compacts the file where no line stands.
    ///
    /// It is the end of every `done` ([`HeldQueue::done`],
    /// [`HeldQueue::done_all`]): the retry, then the compaction once the
    /// queue holds no line ([`HeldQueue::compact`]).
    fn settle(&mut self) -> Settled {
        self.retry();
        let unremoved = if self.lines.is_empty() { self.compact() } else { None };
        Settled { unremoved }
    }

    /// Removes the file of a queue that holds no line: the compaction.
    ///
    /// Every `done` the file still owes goes with it. The ordinals run on:
    /// the queue keeps the greatest it has named, and the hold's counter,
    /// which every line's ordinal comes from, is never wound back (the
    /// module doc's THE ORDINALS; [`MAX_ORDINAL`] states why the space is not
    /// at risk). A removal the volume refuses leaves the file standing, every
    /// line in it `done` or owed its `done`, the store appending on to it,
    /// and is answered by the file's path and the refusal. A file not yet
    /// read is never removed: it may hold an earlier run's lines.
    fn compact(&mut self) -> Option<(PathBuf, io::Error)> {
        if self.disk.opened {
            if let Err(e) = self.disk.remove() {
                return Some((self.disk.path.clone(), e));
            }
        }
        self.held_bytes = 0;
        None
    }

    /// Returns whether the queue's file is a pending directory's (the module
    /// doc), whose lines go to the board's own file once `H.1` reads.
    pub fn is_pending(&self) -> bool {
        matches!(self.disk.named, Named::Pending { .. })
    }

    /// Returns the account the queue's file names in its header: the file's
    /// own where it was read, else the one its header will name.
    #[cfg(test)]
    pub(crate) fn account(&self) -> Option<&str> {
        Some(self.disk.account.as_str())
    }

    /// Returns the `board` the queue's file names in its header: a board's
    /// chain, or the origin a pending file carries.
    #[cfg(test)]
    pub(crate) fn board(&self) -> Option<String> {
        Some(self.disk.named.board())
    }

    /// Names the pending file whose standing lines this queue has taken:
    /// the file of the queue this one replaced at the pending → chain
    /// change, or an earlier run's joined at the first touch (the module
    /// doc).
    ///
    /// `standing` are the lines the file holds standing, by the ordinal each
    /// has here: each is parked while its copy here is owed
    /// ([`HeldQueue::parked`]). The retry removes the file once no copy is
    /// owed ([`HeldQueue::retry`]), so a crash before then leaves both files
    /// for the next launch's join, which enters no line twice; a removal the
    /// device refuses is kept for the next retry and answered
    /// ([`HeldQueue::superseded`]).
    pub fn supersede(&mut self, pending: PathBuf, standing: BTreeSet<u64>) {
        self.disk.superseded = Some(Superseded { path: pending, refused: None, standing });
        self.retry();
    }

    /// Returns whether line `k` is parked: it stands on the pending file this
    /// queue's file took its lines from, and its copy here is owed.
    ///
    /// A parked line is sent by no walk until its copy lands (I5): sent and
    /// kept meanwhile, the one copy of it on disk — the pending file's,
    /// which a device refusing this file's copies refuses a mark on too —
    /// would read it as never sent, and a relaunch would send it again. A
    /// line held in memory alone, on no file, is sent as the board takes it:
    /// a close loses it, and doubles nothing.
    pub fn parked(&self, k: u64) -> bool {
        self.disk.superseded.as_ref().is_some_and(|superseded| superseded.standing.contains(&k)) && !self.disk.holds(k)
    }

    /// Returns the ordinals of the standing lines whose first copy is in the
    /// queue's file.
    pub fn standing_on_disk(&self) -> BTreeSet<u64> {
        self.lines.iter().map(|line| line.k).filter(|&k| self.disk.holds(k)).collect()
    }

    /// Returns the pending file this queue took its lines from, while it
    /// stands: its path, and the refusal of its removal where the retry met
    /// one, for the shell to say.
    pub fn superseded(&self) -> Option<(&Path, Option<&io::Error>)> {
        self.disk.superseded.as_ref().map(|superseded| (superseded.path.as_path(), superseded.refused.as_ref()))
    }

    /// Joins into this queue the standing lines of `from`: an ordered insert,
    /// every line entered a copy owed this queue's file.
    ///
    /// It is the module doc's join: `from` is this run's queue — the one
    /// this queue replaces at the pending → chain change, or the queue the
    /// hold kept while the file could not be read ([`HeldQueue::unopened`])
    /// — whose lines keep their ordinals ([`Joining::ThisRun`]); or an
    /// earlier run's pending file, read at the first touch beside the chain
    /// file ([`Joining::EarlierRun`]). Each line enters under the ordinal
    /// `how` gives it — its own, kept, or the next fresh one from the
    /// principal's counter — and is inserted where that ordinal falls, the
    /// queue kept in `k` order though the file holds the copy after every
    /// line written before it; a line `how`'s repeat test finds standing here
    /// already is not entered again, so a join cut before its copy's sync, or
    /// before the pending file's removal, re-runs at the next launch over the
    /// lines the device kept and doubles none of them. No ordinal a standing
    /// line holds moves (the module doc's THE ORDINALS): a file read here
    /// after the first touch that holds a line under an ordinal below the
    /// hold's counter — past every ordinal this run gave out, `from`'s among
    /// them — is the hold's to renumber first ([`HeldQueue::renumber`]).
    ///
    /// Each line enters at once, with its `base`, frame, anchors, reason and
    /// `time` as `from` held them, OWED its first copy; then the retry runs
    /// ([`HeldQueue::retry`]): the copies owed before them first, then the
    /// lines entering, as ONE copy — every line in one `write`, then one
    /// `sync_data`, the header its own copy before them where the file is
    /// new — one by one where the device refuses it, each that lands kept,
    /// the rest still owed and written by the next retry. The queue's bytes
    /// count each line's frame and anchors, and no budget refuses one — the
    /// join enters what stood, as a reopen reads a file whole, and the queue
    /// holds nothing more until it drains below its budgets. The counter
    /// moves past every fresh ordinal given out. A fresh ordinal past
    /// [`MAX_ORDINAL`] ends the entering there, the lines after it left in
    /// `from`, counted ([`Joined::left`]).
    pub fn join(&mut self, from: &HeldQueue, how: Joining<'_>) -> Joined {
        let fresh = match &how {
            Joining::ThisRun => None,
            Joining::EarlierRun { next_k } => Some(**next_k),
        };
        let Entering { lines, joined, next_k } = self.entering(from, fresh);
        self.enter(lines);
        if let (Joining::EarlierRun { next_k: counter }, Some(next_k)) = (how, next_k) {
            *counter = next_k;
        }
        self.retry();
        joined
    }

    /// Returns the lines of `from` a join enters.
    ///
    /// Each takes its ordinal here — its own, or, where `fresh` names the
    /// counter's next, the next fresh one in order ([`Joining`]) — its other
    /// members as `from` holds them. A line the repeat test finds standing
    /// here is counted `repeated` and passed over: this run's line by its
    /// ordinal; an earlier run's by what it carries ([`carried`]), the
    /// standing lines counted before the first line of `from` is read and
    /// each answering for one line at most, so a line entering is never
    /// matched against another that enters. A fresh ordinal past
    /// [`MAX_ORDINAL`] ends the entering, the lines from there on counted
    /// `left`.
    fn entering(&self, from: &HeldQueue, fresh: Option<u64>) -> Entering {
        let by_ordinal: BTreeSet<u64> = if fresh.is_none() { self.lines.iter().map(|l| l.k).collect() } else { BTreeSet::new() };
        let mut by_carried: HashMap<Carried<'_>, usize> = HashMap::new();
        if fresh.is_some() {
            for line in &self.lines {
                *by_carried.entry(carried(line)).or_default() += 1;
            }
        }
        let mut entering = Entering { next_k: fresh, ..Entering::default() };
        for (n, line) in from.lines.iter().enumerate() {
            let repeated = match fresh {
                None => by_ordinal.contains(&line.k),
                Some(_) => by_carried.get_mut(&carried(line)).filter(|count| **count > 0).map(|count| *count -= 1).is_some(),
            };
            if repeated {
                entering.joined.repeated += 1;
                continue;
            }
            let k = entering.next_k.unwrap_or(line.k);
            if k > MAX_ORDINAL {
                entering.joined.left = from.lines.len() - n;
                break;
            }
            // `k` is within MAX_ORDINAL, so its successor is a `u64`.
            if let Some(next) = entering.next_k.as_mut() {
                *next = k + 1;
            }
            entering.joined.entered.push((line.k, k));
            entering.lines.push(HeldLine { k, ..line.clone() });
        }
        entering
    }

    /// Enters `lines`, each under its ordinal and owed its first copy, the
    /// queue kept in `k` order: the ordered insert.
    ///
    /// `lines` are in `k` order among themselves, none under an ordinal a
    /// standing line holds; the queue's bytes count each, and the greatest
    /// ordinal named moves past them.
    fn enter(&mut self, lines: Vec<HeldLine>) {
        if lines.is_empty() {
            return;
        }
        self.greatest_k = lines.iter().fold(self.greatest_k, |greatest, line| greatest.max(line.k));
        self.held_bytes = lines.iter().fold(self.held_bytes, |bytes, line| bytes.saturating_add(line.held_bytes()));
        self.disk.owing.get_or_insert_with(Box::default).first.extend(lines.iter().map(|line| line.k));
        let standing = std::mem::take(&mut self.lines);
        let mut merged = Vec::with_capacity(standing.len() + lines.len());
        let (mut standing, mut entering) = (standing.into_iter().peekable(), lines.into_iter().peekable());
        loop {
            match (standing.peek(), entering.peek()) {
                (Some(here), Some(new)) if here.k < new.k => merged.extend(standing.next()),
                (Some(_), Some(_)) | (None, Some(_)) => merged.extend(entering.next()),
                (Some(_), None) => merged.extend(standing.next()),
                (None, None) => break,
            }
        }
        self.lines = merged;
    }

    /// Gives every standing line a fresh ordinal from `next_k`, in `k` order.
    ///
    /// It is the one renumbering (the module doc's THE ORDINALS), the hold's
    /// step for a file read after the first touch — the board's own file,
    /// which could not be named until `H.1` read, at the pending → chain
    /// change; or the file the hold could not read at the first touch, read
    /// later — that holds a line under an ordinal below the hold's counter,
    /// which is past every ordinal this run gave out, standing or settled
    /// (skep #875): this run's lines keep theirs, answered already, and the
    /// file's take ordinals from the counter, so none takes an ordinal a call
    /// or the page may hold and they walk after this run's in their file's
    /// order (the owner's ruling, the module doc's THE ORDER). It is
    /// harmless: no line of the file is in the hold's queue, so no ordinal of
    /// it was ever answered to a call or a page. One copy, one sync, made
    /// before any line of this run's is entered: a `done … dropped` of each
    /// line's old ordinal — the one form that raises no base, and said of no
    /// act of the person's; a reader of the file finds the line held again
    /// under its fresh ordinal right after — then each line's `held` copy
    /// under its fresh ordinal, in `k` order, the `done`s first so no fresh
    /// ordinal re-marks a line still standing under it. The queue takes the
    /// fresh ordinals once the copy lands, and `next_k` moves past them, so a
    /// line's copy on disk never reads another ordinal than the queue's.
    /// Nothing spends the re-mark budget: each `held` copy is a first copy
    /// under its ordinal. It answers each line's old and fresh ordinal.
    ///
    /// **Precondition.** The queue's file is read, and no copy is owed it:
    /// the file as the open read it, taken by no hold yet.
    ///
    /// # Errors
    ///
    /// Returns [`RenumberRefused`], nothing renumbered and `next_k` as it
    /// was: the writer refuses a fresh ordinal past [`MAX_ORDINAL`] or a line
    /// past [`MAX_HELD_LINE_BYTES`], at that line; or the device refuses the
    /// copy, at the first line, its bytes cut back off the file, or left past
    /// its whole lines where the cut-back is refused too — whole lines a
    /// fresh read takes for the renumbering landed, which it is as good as.
    pub fn renumber(&mut self, next_k: &mut u64) -> Result<Vec<(u64, u64)>, RenumberRefused> {
        let Some(first_k) = self.lines.first().map(|line| line.k) else { return Ok(Vec::new()) };
        let mut k = *next_k;
        let mut moved = Vec::with_capacity(self.lines.len());
        let mut copy = Vec::new();
        for line in &self.lines {
            copy.extend(done_line_bytes(line.k, Done::Dropped));
        }
        for line in &self.lines {
            let refused = |error: io::Error| RenumberRefused { k: line.k, error };
            if k > MAX_ORDINAL {
                return Err(refused(io::Error::new(io::ErrorKind::InvalidInput, format!("the ordinal {k} is past the held store's {MAX_ORDINAL}"))));
            }
            let bytes = held_line_bytes(&HeldLine { k, ..line.clone() });
            if let Some(error) = past_the_line_bound(&bytes) {
                return Err(refused(error));
            }
            copy.extend_from_slice(&bytes);
            moved.push((line.k, k));
            // `k` is within MAX_ORDINAL, so its successor is a `u64`.
            k += 1;
        }
        if let Err(error) = self.disk.ensure_header().and_then(|()| self.disk.append(&copy)) {
            return Err(RenumberRefused { k: first_k, error });
        }
        for (line, &(_, fresh)) in self.lines.iter_mut().zip(&moved) {
            line.k = fresh;
        }
        self.greatest_k = self.greatest_k.max(k - 1);
        *next_k = k;
        Ok(moved)
    }
}

/// Whose lines a join enters ([`HeldQueue::join`]): the rule each line's
/// ordinal and the repeat test follow (the module doc's THE ORDINALS).
#[derive(Debug)]
pub enum Joining<'a> {
    /// This run's queue — the one replaced at the pending → chain change,
    /// or the one kept while the file could not be read: each line keeps
    /// the ordinal the principal's counter gave it, and one whose ordinal a
    /// standing line already holds is that line — this run's ordinals name
    /// one line each — entered no second time.
    ThisRun,
    /// An earlier run's file, read at the first touch: each line takes the
    /// next ordinal from `next_k`, the principal's counter, in the file's
    /// order — that run's ordinals were its own, and none was answered in
    /// this one — and one a standing line already carries by `doc`, `id` and
    /// frame is passed over, each standing line answering for one such line
    /// at most.
    EarlierRun { next_k: &'a mut u64 },
}

/// What a join entered ([`HeldQueue::join`]), for the caller to say.
#[derive(Debug, Default)]
pub struct Joined {
    /// Each line entered: the ordinal it had in the queue it came from, and
    /// the one it took here — the same for this run's lines.
    pub entered: Vec<(u64, u64)>,
    /// The lines not entered again: a standing line here is each, or
    /// carries it, one standing line answering for one of them at most.
    pub repeated: usize,
    /// The lines left in the queue joined from: those from the first whose
    /// fresh ordinal would pass [`MAX_ORDINAL`] on.
    pub left: usize,
}

/// Why a renumbering was refused, nothing renumbered ([`HeldQueue::renumber`]).
#[derive(Debug)]
pub struct RenumberRefused {
    /// The ordinal, as the file names it, of the line the refusal names.
    ///
    /// It is the line the writer refused, or the file's first line where the
    /// device refused the copy or the file's header.
    pub k: u64,
    /// The refusal: the writer's or the device's.
    pub error: io::Error,
}

/// The lines a join enters, and what the join says of them
/// ([`HeldQueue::join`]).
#[derive(Debug, Default)]
struct Entering {
    /// The lines, each under the ordinal it takes here, in `k` order.
    lines: Vec<HeldLine>,
    joined: Joined,
    /// The counter's next ordinal once the lines enter, where the lines are
    /// an earlier run's and take fresh ones ([`Joining::EarlierRun`]).
    next_k: Option<u64>,
}

/// What a held line carries for the join's repeat test across runs: its
/// document, its `id` and its frame's spelling, never its ordinal
/// ([`Joining::EarlierRun`]).
type Carried<'a> = (&'a str, Option<&'a str>, String);

/// Returns what `line` carries for the join's repeat test across runs.
///
/// The frame's spelling is its compact JSON, which the line's copy spells
/// on disk and a frame read back from it spells again — an object's members
/// sorted, so two frames are equal where their spellings are — and a line a
/// crash left in the file carries what the line it was copied from does.
fn carried(line: &HeldLine) -> Carried<'_> {
    (&line.doc, line.id.as_deref(), line.frame.to_string())
}

impl Disk {
    /// Returns whether line `k`'s first copy stands in the file.
    ///
    /// It does where the file is read and the line is not among those
    /// waiting for their first copy ([`Owing::first`]); nothing stands in a
    /// file not yet read.
    fn holds(&self, k: u64) -> bool {
        self.opened && self.owing.as_ref().is_none_or(|o| !o.first.contains(&k))
    }

    /// Removes the pending file whose lines this file took, where one
    /// stands ([`Superseded`]): the retry's step once no copy is owed.
    ///
    /// A removal the device refuses leaves the file standing for the next
    /// retry, its refusal kept for the shell to say; a file that went, or
    /// none that stood, is gone.
    fn remove_superseded(&mut self) {
        let Some(superseded) = self.superseded.as_mut() else { return };
        match file::remove(&superseded.path) {
            Ok(_) => self.superseded = None,
            Err(e) => superseded.refused = Some(e),
        }
    }

    /// Writes the retry's copies in order: one copy, or one by one if refused.
    ///
    /// It is the retry's write (§3c.3; skep #822). The header goes first
    /// where the file is new ([`Disk::ensure_header`]), its own copy. Two
    /// copies or more are then ONE append ([`Disk::append`]) — every line of
    /// them in one `write`, then one `sync_data` — so they cost one sync
    /// whatever their number; only where the device refuses it, its bytes
    /// cut back off the file, are they appended one by one, in order, up to
    /// the first refused again. A lone copy is tried once. Each copy is one
    /// line within [`MAX_HELD_LINE_BYTES`], as the retry checked it, so the
    /// one append is no line of its own: it passes the bound where its lines'
    /// sum does, and the reader reads each line whole.
    ///
    /// # Errors
    ///
    /// Returns the position in `copies` of the first copy not written, every
    /// copy before it on disk, and its refusal: the header's, at the first
    /// copy, or the device's, of that copy appended alone.
    fn write_copies(&mut self, copies: &[OwedCopy]) -> Result<(), (usize, io::Error)> {
        if copies.is_empty() {
            return Ok(());
        }
        self.ensure_header().map_err(|e| (0, e))?;
        if copies.len() > 1 {
            let lines: Vec<&[u8]> = copies.iter().map(|copy| copy.bytes.as_slice()).collect();
            if self.append(&lines.concat()).is_ok() {
                return Ok(());
            }
        }
        for (n, copy) in copies.iter().enumerate() {
            self.append(&copy.bytes).map_err(|e| (n, e))?;
        }
        Ok(())
    }

    /// Owes line `k` a copy of its state now, spelled `bytes`, which the
    /// retry writes (`HeldQueue::retry`).
    ///
    /// It is every re-mark's, raise's and shift's copy of a line on disk. A
    /// copy owed the line already carries the state, and spends nothing more;
    /// one owed afresh spends the re-mark budget as it is first tried, so a
    /// device that refuses it spends the budget all the same, save where
    /// `spends` is false — a line's mark of `sent`, copied as a hold's line
    /// is (`HeldQueue::restate`). Its retry spends none.
    ///
    /// # Errors
    ///
    /// Returns the writer's refusals, before any I/O, the copy owed never: a
    /// line past [`MAX_HELD_LINE_BYTES`] — a copy owed the line already then
    /// owed no more, the file keeping the copy before it — and a `FileTooLarge`
    /// error for a copy that would pass [`MAX_HELD_REMARK_BYTES`].
    fn owe_mark(&mut self, k: u64, bytes: &[u8], spends: bool) -> io::Result<()> {
        let owing = self.owing.get_or_insert_with(Box::default);
        if let Some(refused) = past_the_line_bound(bytes) {
            owing.owed.remove(&k);
            return Err(refused);
        }
        if spends && !owing.owed.contains_key(&k) {
            let line_bytes = bytes.len().saturating_sub(1);
            let remark_bytes = self.remark_bytes.saturating_add(line_bytes);
            if remark_bytes > MAX_HELD_REMARK_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::FileTooLarge,
                    format!("the held file's re-marks hold {} bytes; this one's {line_bytes} would pass its {MAX_HELD_REMARK_BYTES}", self.remark_bytes),
                ));
            }
            self.remark_bytes = remark_bytes;
        }
        owing.owed.insert(k, Due::Mark);
        Ok(())
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

    /// Appends `bytes` where the file's last whole line ends, and syncs them.
    ///
    /// They are one line and its `\n`, or several lines each with its own —
    /// the retry's one copy ([`Disk::write_copies`]), or a join's
    /// ([`HeldQueue::join`]). The sync comes before the caller builds its
    /// answer (persist-first).
    ///
    /// It is `file::Appender`, opened at the count of whole lines this store
    /// made or read (`open_at`), with this store's copy body
    /// ([`write_synced`]) and `OnTail::Cut`: a tail past the whole lines — a
    /// crash's torn line, or a refused copy whose cut-back failed — is cut
    /// off first, so no line is written after bytes no reader reads, which
    /// would glue the two into one line the reader halts on (P38); the cut
    /// takes only a tail, never a byte of a whole line. A copy the device
    /// refuses — its write cut short, or its sync refused — is cut back off
    /// the file, best effort, so the file holds its whole lines alone and no
    /// later line lands behind pages a refused sync may never have written;
    /// where that cut fails, its failure is named beside the refusal, the
    /// disk keeps that the copy's bytes stand past the whole lines
    /// (`tail_left`), and the next copy's first cut takes them, or the
    /// retry's where no copy is owed ([`Disk::cut_tail`]). Two `#[cfg(test)]`
    /// seams stand in for the device: one reads the file after the sync, so a
    /// suite pins the lines on disk before the answer is built, and one
    /// refuses the cut-back of a copy refused, its bytes left standing.
    ///
    /// **Unverified here** (§3c.3, the record §7 items 2–3): that one small
    /// `write_all` is one `write(2)` (and may split for a large buffer, as a
    /// copy of many lines is — the torn-last-line rule and the cut before
    /// each copy cover either, a crash before the sync taken to leave the
    /// copy's bytes in their order, its whole lines read and its last torn),
    /// and that `sync_data` orders the lines before the answer, is Rust's std
    /// and APFS's `F_FULLFSYNC` — the barrier the kernel's own durability
    /// assumes, not measured here. The write-ahead variant (every burst
    /// appended before its dial, tombstoned at its ack, so even the burst in
    /// flight survives a crash) is named and not taken for a burst's first
    /// dial (§3c.6): R14's bound does not ask it, and the typing cadence would
    /// pay a synced append and tombstone churn. A held line's resend marks the
    /// line `sent` before it dials: its one write ahead of a dial, a re-mark
    /// of a line on disk.
    ///
    /// # Errors
    ///
    /// The open's, the first cut's, the write's or the sync's I/O error; a
    /// first cut that fails writes nothing.
    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        let line = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        let mut file = Appender::open_at(&self.path, self.whole_bytes)?;
        if let Err(failed) = file.append_by_telling(line, OnTail::Cut, Fsync::None, write_synced) {
            #[cfg(test)]
            let failed = tests::cut_back_refused(&self.path, line, failed);
            self.tail_left |= failed.cut_back.is_some();
            return Err(failed.into());
        }
        self.whole_bytes = file.whole();
        self.tail_left = false;
        #[cfg(test)]
        tests::after_sync(&self.path);
        Ok(())
    }

    /// Cuts the bytes a refused copy left past the file's whole lines, where
    /// its cut-back was refused too (`tail_left`): the retry's cut where no
    /// copy is owed ([`HeldQueue::retry`]).
    ///
    /// The cut is synced, and a cut refused leaves the mark standing for the
    /// next retry; a file that went holds no tail.
    fn cut_tail(&mut self) {
        if !self.tail_left {
            return;
        }
        let cut = Appender::open_at(&self.path, self.whole_bytes).and_then(|mut file| file.cut(Fsync::Data));
        #[cfg(test)]
        note_cut_sync(&cut);
        match cut {
            Ok(_) => self.tail_left = false,
            Err(e) if e.kind() == io::ErrorKind::NotFound => self.tail_left = false,
            Err(_) => {}
        }
    }

    /// Removes the file; the directory stays.
    ///
    /// A file that went, or none that stood, is gone: the next line
    /// recreates it, header first, with a re-mark budget of its own, and the
    /// copies it owed go with it — no line of a file that is gone stands to
    /// be re-marked or settled. A removal the volume refuses leaves the file
    /// standing, every line in it `done` or owed its `done`, and the store
    /// appends on to it — `created`, the counts and the copies owed kept — so
    /// no later line is refused `AlreadyExists` and kept in memory alone; the
    /// failure is answered for the shell to say.
    ///
    /// # Errors
    ///
    /// The unlink's I/O error other than a file not found, which is gone.
    fn remove(&mut self) -> io::Result<()> {
        file::remove(&self.path)?;
        self.created = false;
        self.headless = false;
        self.whole_bytes = 0;
        self.tail_left = false;
        self.remark_bytes = 0;
        self.owing = None;
        Ok(())
    }
}

/// Writes `bytes` whole to `file`, then syncs them: one copy's body.
///
/// It is the body of the header's copy and of every copy of lines — one
/// line, or the several of the retry's copy (`Disk::write_copies`) or a
/// join's (`HeldQueue::join`) — handed to `file::write_once_by`,
/// `file::Appender::append_by` and `file::Appender::append_by_telling` as the
/// write, its `sync_data` run before the caller builds its answer
/// (persist-first). Two
/// `#[cfg(test)]` seams stand in for a device that refuses part-way: the
/// first bytes written and the rest refused, as a full disk does
/// (`tests::torn_write`), or the sync refused (`store_unwritable`, which the
/// `held` answer carries as `unwritable`), its kind the one a suite sets —
/// a full disk's, or a read-only volume's (`tests::refused_as`).
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
        return Err(io::Error::new(tests::refused_as(), "the held store's sync was made to fail"));
    }
    #[cfg(test)]
    note_sync();
    file.sync_data()
}

/// The syncs the held file has made since the count was last taken: the
/// suites' measure of what each act costs under the board lock.
///
/// It counts every `sync_data` a copy's body makes ([`write_synced`]: a
/// header's, a line's, a re-mark's, a `done`'s, the retry's one copy and a
/// join's) and the cut's sync where the retry cuts a refused copy's tail
/// ([`Disk::cut_tail`]) — the two syncs the file makes. Process-wide: a
/// suite reads it under nextest, one process per test, and resets it at a
/// cell's start ([`take_syncs`]); `cargo test`'s shared process would mix
/// the counts of the cells it runs beside one another.
#[cfg(test)]
static SYNCS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Counts one sync the held file made ([`SYNCS`]).
#[cfg(test)]
fn note_sync() {
    SYNCS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// Counts the cut's sync, where a tail was cut ([`SYNCS`]): a cut of a file
/// that went, or none to make, syncs nothing.
#[cfg(test)]
fn note_cut_sync<T>(cut: &io::Result<Option<T>>) {
    if matches!(cut, Ok(Some(_))) {
        note_sync();
    }
}

/// Returns the syncs the held file has made since the last call, and resets
/// the count ([`SYNCS`]).
#[cfg(test)]
pub(crate) fn take_syncs() -> u64 {
    SYNCS.swap(0, std::sync::atomic::Ordering::SeqCst)
}

/// Returns the writer's refusal of `bytes`, where they spell a line past
/// [`MAX_HELD_LINE_BYTES`], its `\n` aside: no line the reader reads.
fn past_the_line_bound(bytes: &[u8]) -> Option<io::Error> {
    (bytes.len() > MAX_HELD_LINE_BYTES + 1).then(|| io::Error::new(io::ErrorKind::InvalidInput, format!("the line is {} bytes, past the held store's {MAX_HELD_LINE_BYTES}", bytes.len() - 1)))
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
pub(crate) mod tests;
