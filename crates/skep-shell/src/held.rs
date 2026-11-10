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
//! (§3c.2). The queue keeps its lines by ordinal beside an entry per
//! document — the lines standing on it, and the floors its kept lines raised
//! them to — and every base is read against its document's floor (`Lines`),
//! so a settle, a count and a raise read and change one document's entry,
//! never the whole queue (skep #816). The person's `send` on a moved
//! document raises a line's `base`
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
//! **Anchors that name held words** (skep #969). An edge of a burst's
//! anchors names a unit by its I-address or, where the unit is one of a held
//! insert's own words, which the board has not minted, by a piece of them
//! ([`AnchorPiece`]): the insert's envelope `id` and the unit's offset. A
//! piece binds once, as its line enters the queue, to the newest line
//! standing before it on its document that carries that `id` — the reader
//! binding in the file's order, a re-mark keeping its line's binding, a join
//! and a renumbering binding as they enter, in `k` order — and is placed as
//! that line leaves: kept with the first I-address its words were minted at
//! ([`HeldQueue::keep`]), every piece bound to it becomes that address
//! advanced by its offset; dropped, or kept with no address the shell could
//! read, the anchors of every line naming it are dropped whole
//! ([`Settled::unplaced`]), such a line held as moved where the board refuses
//! it as typed against an older state. The kept line's `done` carries the
//! address as its `addr`, so a reopen places the pieces from it as it derives
//! a raise, and no line is rewritten to carry it. A line naming the words of
//! a line before it is never sent while that line stands — each document's
//! lines go out in `k` order, a line only once the one before it is kept —
//! so no piece reaches the board or the shift.
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
//! **What the file owes, read** (§3c.3; skep #860). A line waiting for its
//! first copy on no file ([`HeldQueue::off_disk`]) is in memory alone, and a
//! close loses it; a line parked on the pending file is not, its copy
//! standing there. The `held` rows read the one line by line and the `held`
//! events the other by document ([`HeldQueue::waits_on`]). A line that has
//! left the queue while a `done` of it is owed is on no row, yet a relaunch
//! lists it as held again, as the file last held it. A native reader counts
//! both ([`HeldQueue::copies_owed`]): the lines in memory alone, and the
//! `done`s owed — this file's, those the pending file it took its lines from
//! never wrote, and the lines that left while parked on that file
//! ([`HeldQueue::supersede`]), counted while it stands.
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
//! launch's reopen and the resend's walk at them measure a few seconds, each
//! in time in proportion to the lines ([`MAX_HELD_LINES`] states the
//! figures). A reopened queue is read
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
use std::ops::Bound;
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
/// refused, so the lines a hold admits bound costs the bytes do not, each in
/// proportion to the lines, as each line's own work reads and changes its
/// document's entry alone (`Lines`; skep #816):
///
/// * the reopen's read at a launch ([`HeldDir::open_file`]), each `done` kept
///   at a position raising the lines standing after it on its document;
/// * the resend's walk on the board's feed thread, each line it settles taken
///   out of the queue ([`HeldQueue::done`]) and the lines after it on its
///   document raised, and each document's lines counted for its `held`
///   event;
/// * the person's drop of a run, each line of it taken out of the queue.
///
/// **Measured** on an Apple M1 Max, at it and [`MAX_HELD_BYTES`] (`held`'s
/// and `hold`'s timing cells, which hold each figure within `TIMED_CEILING`
/// and each line's work, its frame the least, within
/// `held::tests::LINEAR_GROWTH` times its time at a quarter of the lines): a
/// drained file — every line on one document held, marked `sent` and kept
/// at a position by a `done`, the last refused — reopens in 0.11 s optimized
/// and 1.1 s unoptimized; the walk's own work over a full queue in memory,
/// the board answering at once, no attest owed and no copy synced or
/// retried, its turns run back to back, takes 0.24 s with every line on one
/// document and 0.28 s with each on its own, 3.6 s and 3.7 s unoptimized;
/// and the person's drop of a refused run of every line takes 0.03 s, 1.0 s
/// unoptimized, most of it each frame's bytes counted as its line leaves. A
/// drain also pays each line's send, as a burst never held pays it but for
/// the copies, none of which the walk's figure holds: the attest a signed
/// session composes, the board's write, and the two copies its mark and its
/// `done` sync to the device, with the retry that writes them — about 11 ms
/// a line here, most of it the two copies.
pub const MAX_HELD_LINES: usize = 16384;

/// The ceiling the timing cells hold each cost at both budgets to.
///
/// It is some seven times the slowest figure [`MAX_HELD_LINES`] states for
/// the build's profile — 0.28 s optimized, 3.7 s unoptimized — and loose on
/// purpose, as a flaky bound is wrong and a loose one honest: the load of a
/// full gate's parallel run stays under it. A cost grown by another power of
/// the lines is the growth check's to fail (`held::tests::LINEAR_GROWTH`).
#[cfg(test)]
pub(crate) const TIMED_CEILING: std::time::Duration = std::time::Duration::from_secs(if cfg!(debug_assertions) { 26 } else { 2 });

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
/// re-mark does, and the hold bounds the shifts a line takes: the line's
/// deadline ends them (`hold::HAND_OVER_DEADLINE`), and a turn of the resend
/// makes at most its steps of them (`hold::TURN_STEPS`); a raise of its
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
    /// reads before it is sent again (§3c.5), and a line handed over reads
    /// before the person's drop drops it (§3c.4; skep #866).
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

/// The longest envelope `id` the shell names a burst by, in bytes.
///
/// It bounds the `id` a session's table keeps a burst under and a follower's
/// `after` (`shell/follow.rs`), and the `burst` an anchor's piece names
/// ([`AnchorPiece`]): a burst whose `id` is longer is sent and held as any
/// burst is, and no follower or piece can name it; an `after` or a piece past
/// it is refused at the `op` row's door.
pub(crate) const MAX_BURST_ID_BYTES: usize = 128;

/// One edge of the span a burst edits, as its anchors name it.
///
/// It is the I-address of a unit the board minted (skep #442), or, for a unit
/// of a held insert's own words, which the board has not minted, a piece of
/// those words (skep #969): bound to the insert's line as its own line enters
/// the queue, and placed at the address the words were minted at as that line
/// is kept (`Lines`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anchor {
    /// The I-address of a unit, in the tumbler-string form the shift splits
    /// ([`i_address`]).
    Address(String),
    /// A unit of a held insert's words, not minted yet.
    Piece(AnchorPiece),
}

impl Anchor {
    /// Returns the edge `v` spells, where it is of its form.
    ///
    /// The form is `null`, the document's edge, answered `None`; an I-address
    /// ([`i_address`]); or a piece `{burst, offset}`, both present and nothing
    /// beside them, `burst` a string of at most [`MAX_BURST_ID_BYTES`] bytes
    /// and `offset` a natural number. Any other value is of no form.
    fn of(v: &Value) -> Option<Option<Anchor>> {
        match v {
            Value::Null => Some(None),
            Value::String(text) if i_address(text).is_some() => Some(Some(Anchor::Address(text.clone()))),
            Value::Object(m) if m.len() == 2 => {
                let burst = m.get("burst")?.as_str().filter(|burst| burst.len() <= MAX_BURST_ID_BYTES)?;
                let offset = m.get("offset")?.as_u64()?;
                Some(Some(Anchor::Piece(AnchorPiece { burst: burst.to_string(), offset })))
            }
            _ => None,
        }
    }

    /// Returns the edge as the bridge and the held file spell it.
    fn json(&self) -> Value {
        match self {
            Anchor::Address(addr) => Value::from(addr.as_str()),
            Anchor::Piece(piece) => json!({"burst": piece.burst, "offset": piece.offset}),
        }
    }

    /// Returns the edge's I-address, where the board minted its unit.
    pub fn address(&self) -> Option<&str> {
        match self {
            Anchor::Address(addr) => Some(addr),
            Anchor::Piece(_) => None,
        }
    }
}

/// A unit of a held insert's words, named before the board mints them.
///
/// It is the unit `offset` positions into the words of the insert whose
/// envelope `id` is `burst`, counted from 0 in positions as the board seats
/// them — a byte of a string, one an atom — as a follower's piece counts them
/// (`shell/follow.rs`; skep #969). Made by [`Anchor::of`] alone (SP-18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorPiece {
    burst: String,
    offset: u64,
}

impl AnchorPiece {
    /// Returns the envelope `id` of the insert whose words the piece names.
    pub fn burst(&self) -> &str {
        &self.burst
    }

    /// Returns the unit's position among the insert's words, from 0.
    pub fn offset(&self) -> u64 {
        self.offset
    }
}

/// The identities a burst's edit is placed by (skep #442, #751, #969).
///
/// They are the page's, sent over the bridge beside the frame and kept with
/// the held line, never on the wire: `before` the unit just before the span
/// the burst edits, `after` the unit just after it, each `None` at the
/// document's edge — an insert at the first position has no unit before it,
/// one at the end none after — and each named by its I-address or, where it
/// is one of a held insert's own words, by a piece of them ([`Anchor`]); and
/// `span` the I-runs of the units the span holds, in V-order, as the page's
/// `image` read gave them: present for a delete and a rearrange, whose span
/// holds units, and absent for an insert, a copy and a reinstate, which place
/// at a point. Where the board refuses the burst as typed against an older
/// state of its document, the shell finds `before` and `after` in the
/// document's current image and, where the units between them are the span's
/// own — none for a placement, so the two stand adjacent — moves every
/// position the burst names by their one displacement and sends it again
/// (`hold::resend`); a burst that carries none — an agent's through the MCP
/// tools — is held as a moved document, and so is a delete or a rearrange
/// that carries no `span`. A piece never reaches the shift: its line is sent
/// only after the line it names leaves the queue, which places it (the module
/// doc). Made by [`Anchors::of`] alone, from the bridge's argument and from
/// the held file's member alike, so every edge kept is one [`Anchor::of`]
/// admits and every run of a span one [`SpanRun`] admits (SP-18), and the
/// whole spells no more than [`MAX_ANCHOR_BYTES`] (SP-17), its bytes counted
/// there once for the queue's budget ([`Anchors::bytes`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchors {
    /// The unit just before the span; `None` at the start.
    pub before: Option<Anchor>,
    /// The unit just after the span; `None` at the end.
    pub after: Option<Anchor>,
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
    /// each an edge of [`Anchor::of`]'s form — `null`, an I-address or a
    /// piece — `span` absent or a non-empty list of runs of [`SpanRun`]'s
    /// form, and nothing beside the three, the whole spelling no more than
    /// [`MAX_ANCHOR_BYTES`] as compact JSON — measured first, before any
    /// member is read; any other value is of no form, which the bridge
    /// refuses `malformed_args` naming `anchors` and the held file's reader
    /// halts on.
    pub fn of(v: &Value) -> Option<Anchors> {
        let bytes = json_len(v);
        if bytes > MAX_ANCHOR_BYTES {
            return None;
        }
        let m = v.as_object().filter(|m| m.keys().all(|k| matches!(k.as_str(), "before" | "after" | "span")))?;
        let span = match m.get("span") {
            None => None,
            Some(Value::Array(runs)) if !runs.is_empty() => Some(runs.iter().map(SpanRun::of).collect::<Option<Vec<_>>>()?),
            Some(_) => return None,
        };
        Some(Anchors { before: Anchor::of(m.get("before")?)?, after: Anchor::of(m.get("after")?)?, span, bytes })
    }

    /// Returns the anchors as the bridge and the held file spell them.
    pub fn json(&self) -> Value {
        let edge = |anchor: &Option<Anchor>| anchor.as_ref().map_or(Value::Null, Anchor::json);
        let mut v = json!({"before": edge(&self.before), "after": edge(&self.after)});
        if let Some(span) = &self.span {
            v["span"] = span.iter().map(SpanRun::json).collect();
        }
        v
    }

    /// Returns the bytes the anchors spell, within [`MAX_ANCHOR_BYTES`].
    ///
    /// It is the length of their compact JSON as [`Anchors::of`] measured
    /// it, which is the length of their spelling on the bridge and in the
    /// held file ([`Anchors::json`]): the form's members are `null`, numbers,
    /// strings of digits and dots, a piece's `burst` escaped by the one
    /// escaper every spelling of it takes, and its own names, so two
    /// spellings of the one value differ in their members' order alone. It is
    /// what a line's anchors spend of the queue's budget ([`MAX_HELD_BYTES`]).
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Returns whether an edge is a piece of a held insert's words.
    pub fn names_pieces(&self) -> bool {
        [&self.before, &self.after].into_iter().any(|edge| matches!(edge, Some(Anchor::Piece(_))))
    }

    /// Returns the anchors with each piece of `burst`'s words placed.
    ///
    /// `minted` is the first I-address the words of the insert whose
    /// envelope `id` is `burst` were minted at, and each piece naming them
    /// becomes that address advanced by its offset (skep #969); every other
    /// edge stands. It answers `None` where an advanced address passes a
    /// `u64` or the anchors would spell past [`MAX_ANCHOR_BYTES`], which no
    /// reader reads.
    pub fn placed(&self, burst: &str, minted: &str) -> Option<Anchors> {
        let (prefix, first) = i_address(minted)?;
        let place = |edge: &Option<Anchor>| match edge {
            Some(Anchor::Piece(piece)) if piece.burst == burst => Some(Some(Anchor::Address(format!("{prefix}.{}", first.checked_add(piece.offset)?)))),
            other => Some(other.clone()),
        };
        let mut anchors = Anchors { before: place(&self.before)?, after: place(&self.after)?, span: self.span.clone(), bytes: 0 };
        anchors.bytes = json_len(&anchors.json());
        (anchors.bytes <= MAX_ANCHOR_BYTES).then_some(anchors)
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
///
/// A queue hands its standing lines out in this form, each a copy whose
/// `base` is raised by every line kept before it on its document
/// ([`HeldQueue::lines`]); it keeps them otherwise, each base its own beside
/// its document's floors (`Lines`).
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
    /// as typed against an older state. A piece among them stands until the
    /// line whose words it names leaves the queue, and is then placed at
    /// their address, or the anchors are dropped where none names them
    /// (skep #969; the module doc).
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

/// A queue's standing lines by ordinal, beside an entry per document.
///
/// It is the one record of a queue's lines (§3c.2), and of a file's as the
/// open reads it ([`HeldDir::open_file`]): each line under its ordinal, in
/// `k` order, and each document's entry — the ordinals standing on it, and
/// the floors its kept lines raised the rest to — so a settle, a count and a
/// raise read and change one document's entry alone, and the raise behind a
/// document's first line walks no line at all (skep #816). A line's base is
/// its own raised by its document's floors ([`Lines::base`]), and every copy
/// of a line and every line handed out reads it so ([`Lines::copy`],
/// [`Lines::handout`]).
///
/// **The raise behind a kept line.** A line kept at a position — its ack's,
/// or the landing the resend's read found: the person's own write — raises
/// to it the base of every line standing after it on its document (§3c.2):
/// a line behind it is never dialed while it stands, so no landing of its
/// own lies below that position, and a base already past it stands. Where
/// the kept line was the document's first, those are every line standing on
/// the document, and the raise is one floor, given under a stamp past every
/// line's: it raises each line that entered before it, and none that enters
/// after. Where a line stands before it — two first dials racing at one
/// document (`Holds::shift_at_first_dial`), or a file that so reads — the
/// lines after it are raised one by one, each its own base.
///
/// **The pieces a line's anchors name** (skep #969). A piece binds once, as its
/// line enters, to the newest line standing before it on its document whose
/// envelope `id` is the piece's `burst` ([`Lines::enter`]), each document
/// keeping its lines by `id` and the queue the lines naming each line, so a
/// binding and a placing read the lines involved alone; anchors a piece of
/// which binds to no line place nothing, and are dropped as the line enters. A
/// line leaving places the pieces bound to it ([`Lines::leave`]).
#[derive(Debug, Default)]
struct Lines {
    /// The standing lines by ordinal.
    by_k: BTreeMap<u64, Standing>,
    /// Each document's entry, while a line stands on it.
    docs: HashMap<String, DocLines>,
    /// The last stamp given: to a line as it entered, or to a floor.
    stamp: u64,
    /// The lines whose anchors' pieces name each line's words, by its ordinal.
    named_by: HashMap<u64, BTreeSet<u64>>,
}

/// One standing line as its queue keeps it ([`Lines`]).
#[derive(Debug)]
struct Standing {
    /// The line, its `base` its own.
    ///
    /// Its document's floors raise it ([`Lines::base`]).
    line: HeldLine,
    /// The stamp it entered under: each floor given after it raises it.
    stamp: u64,
    /// The ordinals of the lines its anchors' pieces are bound to.
    ///
    /// They are `before`'s and `after`'s, `None` where the edge is no piece.
    names: [Option<u64>; 2],
}

/// One document's entry among a queue's lines ([`Lines`]).
#[derive(Debug, Default)]
struct DocLines {
    /// The ordinals of the lines standing on the document.
    ks: BTreeSet<u64>,
    /// The floors the document's kept lines gave, each `(stamp, at)`.
    ///
    /// A floor raises to `at` each line stamped before it. Along the list
    /// the stamps rise and the positions fall: a floor no higher than one
    /// given after it raises no line that one does not raise as far, so it
    /// is dropped as that one is given ([`DocLines::give`]).
    floors: Vec<(u64, u64)>,
    /// The ordinals standing on the document by the envelope `id` each line
    /// carries.
    ids: HashMap<String, BTreeSet<u64>>,
}

/// What a line's leaving did to the lines whose pieces named its words.
///
/// It is [`Lines::leave`]'s account, for the queue's budget and the shell's
/// window.
#[derive(Debug, Default)]
struct Placing {
    /// The bytes those lines' anchors spent of the queue's budget before.
    spent: usize,
    /// The bytes they spend now.
    spends: usize,
    /// The lines whose anchors were dropped, no address naming the words.
    unplaced: Vec<u64>,
}

impl DocLines {
    /// Returns the floor of a line stamped `stamp`, where one raises it.
    ///
    /// It is the highest of the floors given after the line: the first of
    /// them, as the positions fall along the list.
    fn floor(&self, stamp: u64) -> Option<u64> {
        let first = self.floors.partition_point(|&(given, _)| given < stamp);
        self.floors.get(first).map(|&(_, at)| at)
    }

    /// Gives the floor `at` under `stamp`, past every stamp given before.
    fn give(&mut self, stamp: u64, at: u64) {
        while self.floors.last().is_some_and(|&(_, below)| below <= at) {
            self.floors.pop();
        }
        self.floors.push((stamp, at));
    }
}

impl Lines {
    /// Returns how many lines stand.
    fn len(&self) -> usize {
        self.by_k.len()
    }

    /// Returns whether no line stands.
    fn is_empty(&self) -> bool {
        self.by_k.is_empty()
    }

    /// Returns the least ordinal standing, where a line stands.
    fn first_k(&self) -> Option<u64> {
        self.by_k.first_key_value().map(|(&k, _)| k)
    }

    /// Returns the greatest ordinal standing, where a line stands.
    fn last_k(&self) -> Option<u64> {
        self.by_k.last_key_value().map(|(&k, _)| k)
    }

    /// Returns whether a line of ordinal `k` stands.
    fn contains(&self, k: u64) -> bool {
        self.by_k.contains_key(&k)
    }

    /// Returns the ordinals standing, in `k` order.
    fn ordinals(&self) -> impl Iterator<Item = u64> + '_ {
        self.by_k.keys().copied()
    }

    /// Returns the ordinals standing on `doc`, where a line stands on it.
    fn ordinals_on(&self, doc: &str) -> Option<&BTreeSet<u64>> {
        self.docs.get(doc).map(|entry| &entry.ks)
    }

    /// Returns how many lines stand on `doc`.
    fn count_on(&self, doc: &str) -> usize {
        self.docs.get(doc).map_or(0, |entry| entry.ks.len())
    }

    /// Returns the reason of line `k`, where it stands.
    fn reason(&self, k: u64) -> Option<&Reason> {
        self.by_k.get(&k).map(|standing| &standing.line.reason)
    }

    /// Returns a standing line's base, raised by its document's floor.
    fn base(&self, standing: &Standing) -> u64 {
        let floor = self.docs.get(&standing.line.doc).and_then(|entry| entry.floor(standing.stamp));
        floor.map_or(standing.line.base, |floor| floor.max(standing.line.base))
    }

    /// Returns a standing line as the queue hands it out.
    ///
    /// It is a copy, its base read against its document's floor.
    fn handout(&self, standing: &Standing) -> HeldLine {
        HeldLine { base: self.base(standing), ..standing.line.clone() }
    }

    /// Returns each standing line in `k` order, as the queue hands it out.
    fn handouts(&self) -> impl Iterator<Item = HeldLine> + '_ {
        self.by_k.values().map(|standing| self.handout(standing))
    }

    /// Returns line `k` as the queue hands it out, where it stands.
    fn line(&self, k: u64) -> Option<HeldLine> {
        self.by_k.get(&k).map(|standing| self.handout(standing))
    }

    /// Returns each line's ordinal and reason on `doc`, in `k` order.
    fn reasons_on(&self, doc: &str) -> impl Iterator<Item = (u64, &Reason)> + '_ {
        let on_doc = self.docs.get(doc).map(|entry| &entry.ks);
        on_doc.into_iter().flatten().filter_map(move |&k| Some((k, self.reason(k)?)))
    }

    /// Returns the first line past the ordinal `after` that `skip` keeps.
    ///
    /// A line is passed over where `skip` answers true for its document; the
    /// line found is handed out as the queue hands it out.
    fn next_after(&self, after: u64, skip: impl Fn(&str) -> bool) -> Option<HeldLine> {
        let mut past = self.by_k.range((Bound::Excluded(after), Bound::Unbounded)).map(|(_, standing)| standing);
        past.find(|standing| !skip(&standing.line.doc)).map(|standing| self.handout(standing))
    }

    /// Returns line `k`'s `held` copy, where it stands.
    ///
    /// Its base is read against its document's floor.
    fn copy(&self, k: u64) -> Option<Vec<u8>> {
        let standing = self.by_k.get(&k)?;
        Some(held_line_bytes(&standing.line, self.base(standing)))
    }

    /// Returns what each line carries for the join's repeat test, by `k`.
    ///
    /// It is the test across runs ([`carried`]).
    fn carried(&self) -> impl Iterator<Item = Carried<'_>> {
        self.by_k.values().map(|standing| carried(&standing.line))
    }

    /// Returns the bytes the standing lines spend of the queue's budget.
    fn held_bytes(&self) -> usize {
        self.by_k.values().map(|standing| standing.line.held_bytes()).sum()
    }

    /// Returns the newest line standing on `doc` before the ordinal `k`
    /// whose envelope `id` is `id`.
    fn newest_with_id(&self, doc: &str, id: &str, k: u64) -> Option<&HeldLine> {
        let &newest = self.docs.get(doc)?.ids.get(id)?.range(..k).next_back()?;
        self.by_k.get(&newest).map(|standing| &standing.line)
    }

    /// Returns whether a standing line's anchors name line `k`'s words.
    fn is_named(&self, k: u64) -> bool {
        self.named_by.contains_key(&k)
    }

    /// Returns the lines `line`'s pieces bind to, `before`'s and `after`'s.
    ///
    /// A piece binds to the newest line standing before `line` on its
    /// document whose envelope `id` is the piece's `burst` (skep #969); it
    /// answers `None` where a piece binds to no line.
    fn binding(&self, line: &HeldLine) -> Option<[Option<u64>; 2]> {
        let mut names = [None, None];
        let Some(anchors) = &line.anchors else { return Some(names) };
        for (name, edge) in names.iter_mut().zip([&anchors.before, &anchors.after]) {
            if let Some(Anchor::Piece(piece)) = edge {
                *name = Some(self.newest_with_id(&line.doc, &piece.burst, line.k)?.k);
            }
        }
        Some(names)
    }

    /// Takes `namer` off the lines that name line `named`'s words.
    fn unname(&mut self, named: u64, namer: u64) {
        if let Some(namers) = self.named_by.get_mut(&named) {
            namers.remove(&namer);
            if namers.is_empty() {
                self.named_by.remove(&named);
            }
        }
    }

    /// Enters `line` under a stamp past every one given, and returns the
    /// bytes it spends of the queue's budget.
    ///
    /// No floor given before it raises it. Each piece of its anchors binds
    /// to the line whose words it names ([`Lines::binding`]), and anchors a
    /// piece of which binds to no line name no place, and are dropped.
    ///
    /// # Panics
    ///
    /// Panics, in a debug build, where a line of its ordinal stands (the
    /// caller's precondition).
    fn enter(&mut self, mut line: HeldLine) -> usize {
        debug_assert!(!self.by_k.contains_key(&line.k), "PRECONDITION of `Lines::enter`: no line of the ordinal {} stands", line.k);
        let names = self.binding(&line).unwrap_or_else(|| {
            line.anchors = None;
            [None, None]
        });
        for named in names.into_iter().flatten() {
            self.named_by.entry(named).or_default().insert(line.k);
        }
        self.stamp += 1;
        let entry = self.docs.entry(line.doc.clone()).or_default();
        entry.ks.insert(line.k);
        if let Some(id) = &line.id {
            entry.ids.entry(id.clone()).or_default().insert(line.k);
        }
        let bytes = line.held_bytes();
        self.by_k.insert(line.k, Standing { line, stamp: self.stamp, names });
        bytes
    }

    /// Puts `line` in its ordinal's place, or enters it where none stands.
    ///
    /// It is a `held` line read under an ordinal that stands, the line's
    /// re-mark ([`HeldDir::open_file`]): taken whole, its base the one it
    /// spells, under a stamp past every floor given, as the writer spelled it
    /// raised by each, its pieces bound again and the lines naming its words
    /// naming it still.
    fn put(&mut self, line: HeldLine) {
        self.take(line.k, None);
        self.enter(line);
    }

    /// Takes line `k` out as it leaves the queue, and places the pieces that
    /// name its words (skep #969).
    ///
    /// The lines standing after it on its document are raised to `raise`
    /// where it names one, as [`Lines::take`] raises them (§3c.2). Each line
    /// whose pieces are bound to it is placed: where `minted` names the first
    /// I-address its words were minted at, every piece naming its `id`
    /// becomes that address advanced by its offset ([`Anchors::placed`]);
    /// where it names none — the line dropped, or kept with no address the
    /// shell could read — or the placed anchors could not be spelled, the
    /// naming line's anchors are dropped whole, a piece being no place the
    /// shift can find. It answers the line and what its leaving did.
    fn leave(&mut self, k: u64, raise: Option<u64>, minted: Option<&str>) -> Option<(HeldLine, Placing)> {
        let line = self.take(k, raise)?;
        let mut placing = Placing::default();
        for namer in self.named_by.remove(&k).into_iter().flatten() {
            let Some(standing) = self.by_k.get_mut(&namer) else { continue };
            let Some(anchors) = standing.line.anchors.take() else { continue };
            placing.spent += anchors.bytes();
            match minted.zip(line.id.as_deref()).and_then(|(minted, id)| anchors.placed(id, minted)) {
                Some(placed) => {
                    placing.spends += placed.bytes();
                    standing.names.iter_mut().filter(|name| **name == Some(k)).for_each(|name| *name = None);
                    standing.line.anchors = Some(placed);
                }
                None => {
                    let names = std::mem::take(&mut standing.names);
                    placing.unplaced.push(namer);
                    for named in names.into_iter().flatten().filter(|&named| named != k) {
                        self.unname(named, namer);
                    }
                }
            }
        }
        Some((line, placing))
    }

    /// Takes line `k` out, where it stands: the line, its base its own.
    ///
    /// Where `raise` names a position — the line kept there — the lines
    /// standing after it on its document are raised to it (§3c.2): by one
    /// floor where the line was the document's first, else one by one
    /// ([`Lines`]). Its own pieces are unbound; the lines naming its words
    /// are [`Lines::leave`]'s to place, and a re-mark's ([`Lines::put`])
    /// name it still.
    fn take(&mut self, k: u64, raise: Option<u64>) -> Option<HeldLine> {
        let Standing { line, names, .. } = self.by_k.remove(&k)?;
        for named in names.into_iter().flatten() {
            self.unname(named, k);
        }
        let entry = self.docs.get_mut(&line.doc).expect("a standing line's document has its entry");
        entry.ks.remove(&k);
        if let Some(id) = &line.id {
            if let Some(ks) = entry.ids.get_mut(id) {
                ks.remove(&k);
                if ks.is_empty() {
                    entry.ids.remove(id);
                }
            }
        }
        let first = entry.ks.first().copied();
        match (raise, first) {
            (Some(at), Some(first)) if first > k => {
                self.stamp += 1;
                entry.give(self.stamp, at);
            }
            (Some(at), Some(_)) => {
                for after in entry.ks.range((Bound::Excluded(k), Bound::Unbounded)) {
                    let behind = &mut self.by_k.get_mut(after).expect("a document's ordinals stand").line;
                    behind.base = behind.base.max(at);
                }
            }
            (None, _) | (_, None) => {}
        }
        if entry.ks.is_empty() {
            self.docs.remove(&line.doc);
        }
        Some(line)
    }

    /// Re-marks line `k` in place, where it stands.
    ///
    /// The line takes `reason`, its base is raised to `raise` where that is
    /// past it, and its `time` is the change's. It is the change every
    /// re-mark makes ([`HeldQueue::remark`],
    /// [`HeldQueue::remark_all`]). It answers whether the re-mark spends the
    /// re-mark budget — one that marks the line `sent` (`marks_sent`) spends
    /// none of it, and every other one is within it — and none where no line
    /// of `k` stands or the line carries the reason and the base already.
    fn restate(&mut self, k: u64, reason: Reason, raise: Option<u64>) -> Option<bool> {
        let standing = self.by_k.get(&k)?;
        let base = self.base(standing);
        let raised = raise.map_or(base, |at| base.max(at));
        if standing.line.reason == reason && raised == base {
            return None;
        }
        let line = &mut self.by_k.get_mut(&k)?.line;
        let spends = !marks_sent(&line.reason, &reason);
        line.reason = reason;
        line.base = raised;
        line.time = now_ms();
        Some(spends)
    }

    /// Rewrites line `k`'s frame in place, where it stands and differs.
    ///
    /// It answers the bytes the line spent of the queue's budget before, and
    /// spends now.
    fn rewrite(&mut self, k: u64, frame: Value) -> Option<(usize, usize)> {
        let line = &mut self.by_k.get_mut(&k)?.line;
        if line.frame == frame {
            return None;
        }
        let spent = line.held_bytes();
        line.frame = frame;
        line.time = now_ms();
        Some((spent, line.held_bytes()))
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
/// `as` is `kept` with an optional `at` and an optional `addr`, an I-address
/// ([`i_address`]; skep #969), or `dropped` with neither, and a `time`
/// stands.
fn is_done_line(m: &Map<String, Value>) -> bool {
    let (at, addr) = (m.get("at"), m.get("addr"));
    let resolved = match m.get("as").and_then(Value::as_str) {
        Some("kept") => at.is_none_or(Value::is_u64) && addr.is_none_or(|addr| addr.as_str().and_then(i_address).is_some()),
        Some("dropped") => at.is_none() && addr.is_none(),
        _ => false,
    };
    resolved && m.get("time").is_some_and(Value::is_u64)
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
    /// writer left it. The lines are keyed by *ordinal* as the file is read
    /// in its order, and the file may hold a lower ordinal's lines after a
    /// higher one's (a join's ordered insert): a `held` line re-marks the
    /// line standing under its ordinal when it is read, wherever that line
    /// lies in the file, and is a new line where none stands; a `done` takes
    /// out the line standing under its ordinal and raises the standing lines
    /// of *higher* ordinals on its document, never the lines written after
    /// it; and the re-mark budget counts a `held` line of a standing ordinal
    /// wherever it lies, so the queue read is the one the writer held, in
    /// `k` order, whatever the file's order. The read holds the lines as the
    /// queue does (`Lines`), each line, re-mark and `done` read in the
    /// file's order taking the step the writer's act took, so a reopen
    /// derives each document's floors as the writer's queue gave them. The
    /// whole lines' bytes are counted
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
        let fresh = |disk: Disk, aside: Option<PathBuf>| Opened::Live { queue: HeldQueue { disk, lines: Lines::default(), greatest_k: 0, held_bytes: 0 }, aside };
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
        let mut lines = Lines::default();
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
                let spends = lines.reason(k).is_some_and(|was| !marks_sent(was, &line.reason));
                lines.put(line);
                if spends {
                    remark_bytes = remark_bytes.saturating_add(line_bytes);
                }
            } else if let Some(done) = m.get("done") {
                let Some(k) = ordinal(done).filter(|_| is_done_line(&m)) else { return halted(HaltWhy::Damaged) };
                max_k = max_k.max(k);
                // A `kept` line at a position raises the lines standing after
                // it on its document, and places the pieces naming its words
                // at its `addr`, as `HeldQueue::done` and `HeldQueue::keep`
                // did; a `done` of no standing line raises none.
                lines.leave(k, m.get("at").and_then(Value::as_u64), m.get("addr").and_then(Value::as_str));
            } else {
                return halted(HaltWhy::Damaged);
            }
        }
        let held_bytes = lines.held_bytes();
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
/// It holds its un-done `held` lines in `k` order, beside each document's
/// entry (`Lines`) — a hold adding none past [`MAX_HELD_LINES`] — and hands
/// them out as copies, each base raised by the lines kept before it
/// ([`HeldQueue::lines`]); beside them, the greatest ordinal it has named,
/// the bytes its
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
    lines: Lines,
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
    /// How each line left that the file holds standing and this queue does
    /// not: a `done` the file never wrote.
    ///
    /// The queue this one replaced owed it, or the line left while parked. A
    /// close before the file's removal leaves each line standing there, for
    /// the next launch's join to read as held.
    left: Vec<Done>,
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

/// What a principal's held file owes its lines, read at one moment (§3c.3).
///
/// It is the native side's count of what a close leaves behind (skep #860),
/// read by `Shell::copies_owed` and crossing no bridge. A re-mark's copy is
/// no part of it: it changes no line's standing, and a relaunch reads such a
/// line as the file last held it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CopiesOwed {
    /// The standing lines no file holds a copy of.
    ///
    /// They wait in memory alone, and a close loses each.
    pub lines: usize,
    /// The lines the board took whose `done` no file holds.
    ///
    /// Each has left the queue and stands in a file, so a relaunch lists it
    /// as held again: one the file marks `sent` is read for its landing and
    /// kept where it landed, and any other goes out again, for the board to
    /// judge as typed against an older state.
    pub kept: usize,
    /// The lines dropped whose `done` no file holds.
    ///
    /// A relaunch lists each as held again, as it stood before the drop.
    pub dropped: usize,
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
#[derive(Debug, Clone)]
enum Due {
    /// The line's state now, written whole.
    Mark,
    /// The line's `done`, the line gone from the queue.
    ///
    /// `bytes` are its frame's and its anchors', which the queue's budget
    /// counts until the `done` lands ([`MAX_HELD_BYTES`]), as a reopen reads
    /// the line standing until then; `addr` the first I-address a kept
    /// insert's words were minted at, where the shell knows it, which the
    /// `done` carries so a reopen places the pieces naming them (skep #969).
    Done { done: Done, bytes: usize, addr: Option<String> },
}

impl Due {
    /// Returns which copy it is, as [`Waiting::owed`] names it.
    fn owed(&self) -> Owed {
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
/// Each line settled — one by [`HeldQueue::done`] or [`HeldQueue::keep`], or
/// a run by [`HeldQueue::done_all`] — has left the queue whatever the disk
/// did: a `done` the device refuses is owed, and waits as every copy owed
/// does ([`HeldQueue::waiting`]).
#[derive(Debug, Default)]
pub struct Settled {
    /// The queue emptied and its file could not be removed.
    ///
    /// The file stands, every line in it `done` or owed its `done`, and the
    /// store appends on to it, its ordinals running on; named by its path.
    pub unremoved: Option<(PathBuf, io::Error)>,
    /// The standing lines whose anchors the settle dropped (skep #969).
    ///
    /// Each named words of a line that left with no address to name them by
    /// — dropped, or kept with none the shell could read — so its anchors
    /// place nothing, and it is held as moved where the board refuses it as
    /// typed against an older state.
    pub unplaced: Vec<u64>,
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
        HeldQueue { disk: dir.disk(principal, account), lines: Lines::default(), greatest_k: 0, held_bytes: 0 }
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

    /// Returns a copy of each un-done `held` line, in `k` order.
    ///
    /// Each line's `base` is its own raised by every line kept before it on
    /// its document (§3c.2). It copies every line the queue holds: an act on
    /// one line, on one document's lines or on their count reads
    /// [`HeldQueue::line`], [`HeldQueue::reasons_on`] or
    /// [`HeldQueue::count_on`], each of which reads that line or that
    /// document's entry alone.
    pub fn lines(&self) -> Vec<HeldLine> {
        self.lines.handouts().collect()
    }

    /// Returns a copy of line `k`, where it stands.
    pub fn line(&self, k: u64) -> Option<HeldLine> {
        self.lines.line(k)
    }

    /// Returns each line's ordinal and reason on `doc`, in `k` order.
    ///
    /// The reasons are read in place, nothing copied.
    pub fn reasons_on(&self, doc: &str) -> impl Iterator<Item = (u64, &Reason)> + '_ {
        self.lines.reasons_on(doc)
    }

    /// Returns a copy of the first line past the ordinal `after` `skip` keeps.
    ///
    /// A line is passed over where `skip` answers true for its document: the
    /// resend's walk, a line at a time (`hold::resend`).
    pub fn next_after(&self, after: u64, skip: impl Fn(&str) -> bool) -> Option<HeldLine> {
        self.lines.next_after(after, skip)
    }

    /// Returns how many un-done lines stand.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Returns whether no un-done line stands.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Returns how many lines stand on `doc`, read off its document's entry.
    pub fn count_on(&self, doc: &str) -> usize {
        self.lines.count_on(doc)
    }

    /// Returns the frame of the newest line standing on `doc` whose envelope
    /// `id` is `id`: the line a piece naming that `id` binds to (skep #969).
    pub fn frame_named(&self, doc: &str, id: &str) -> Option<&Value> {
        self.lines.newest_with_id(doc, id, u64::MAX).map(|line| &line.frame)
    }

    /// Returns whether a standing line's anchors name line `k`'s words.
    pub fn is_named(&self, k: u64) -> bool {
        self.lines.is_named(k)
    }

    /// Returns the least ordinal a standing line holds, where one stands.
    pub fn first_k(&self) -> Option<u64> {
        self.lines.first_k()
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
    /// (skep #442), none where the burst carried none, each piece among them
    /// bound to the line whose words it names (`Lines`; skep #969); their
    /// bytes spend the queue's budget beside the frame's. It answers the
    /// ordinal the line took
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
        assert!(self.lines.last_k().is_none_or(|last| last < k), "PRECONDITION of `HeldQueue::hold`: the ordinal {k} is past every one a standing line holds");
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
        self.held_bytes += self.lines.enter(line);
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
    /// as it was first tried — each line owed a copy found by its ordinal, and
    /// no other line read. They are *one* copy — every line of them in one
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
        let on_disk = owing.owed.iter().filter_map(|(&k, due)| {
            let bytes = match due {
                // A line no longer standing owes no copy of its state.
                Due::Mark => self.lines.copy(k)?,
                Due::Done { done, addr, .. } => done_line_bytes(k, *done, addr.as_deref()),
            };
            Some(OwedCopy { k, owed: due.owed(), bytes })
        });
        let first = owing.first.iter().filter_map(|&k| Some(OwedCopy { k, owed: Owed::Line, bytes: self.lines.copy(k)? }));
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
        let Some(spends) = self.lines.restate(k, reason, None) else { return Ok(()) };
        self.owe(k, spends)
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
            let Some(spends) = self.lines.restate(k, reason, raise) else { continue };
            changed = true;
            if let Err(e) = self.owe_copy(k, spends) {
                refused.push((k, e));
            }
        }
        if changed {
            self.retry();
        }
        refused
    }

    /// Owes the copy of line `k`'s state now, and runs the retry.
    ///
    /// It is one change's copy ([`HeldQueue::owe_copy`]), which the retry
    /// writes in its place in `k` order, behind every copy owed before it
    /// ([`HeldQueue::retry`]).
    ///
    /// # Errors
    ///
    /// Returns the writer's refusal, the copy owed never.
    fn owe(&mut self, k: u64, spends: bool) -> io::Result<()> {
        let owed = self.owe_copy(k, spends);
        self.retry();
        owed
    }

    /// Owes the copy of line `k`'s state now, for the next retry.
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
    fn owe_copy(&mut self, k: u64, spends: bool) -> io::Result<()> {
        if !self.disk.holds(k) {
            return Ok(());
        }
        let Some(copy) = self.lines.copy(k) else { return Ok(()) };
        self.disk.owe_mark(k, &copy, spends)
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
        let Some((spent, spends)) = self.lines.rewrite(k, frame) else { return Ok(()) };
        self.held_bytes = self.held_bytes.saturating_sub(spent).saturating_add(spends);
        self.owe(k, true)
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
    /// **The pieces naming its words** (skep #969). A line that leaves here
    /// names no address its words were minted at, so the anchors of every
    /// line whose pieces name its words are dropped ([`Settled::unplaced`]):
    /// a kept insert whose address the shell knows leaves by
    /// [`HeldQueue::keep`], which places them.
    ///
    /// **The base behind a kept line.** A line kept at a position raises to
    /// it the `base` of every line held after it on its document, a base
    /// already past it standing (§3c.2): that position is the person's own
    /// write — its ack's, or the landing the resend's read found — and a line
    /// behind it is never dialed while it stands (§3c.4's `behind`), so no
    /// landing of its own lies below it. The raise reads and changes the
    /// line's document's entry alone, one floor where the line was its
    /// document's first (`Lines`), and a reopen raises them again from the
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
        let unplaced = self.leave(k, done, None)?;
        Ok(self.settle(unplaced))
    }

    /// Resolves line `k` kept at `at`, its words minted from `minted`.
    ///
    /// It is [`HeldQueue::done`] with [`Done::Kept`] (§3c.2), save that
    /// `minted` — the first I-address the board minted a kept insert's words
    /// at, where the shell knows it — places every piece naming the line's
    /// words at that address advanced by its offset (skep #969), and rides
    /// the line's `done` as its `addr`, so a reopen places them from it as it
    /// derives a raise and no line is rewritten to carry it. A line naming
    /// the words whose placed anchors could not be spelled has its anchors
    /// dropped, as at a line that leaves with no address
    /// ([`Settled::unplaced`]).
    ///
    /// # Errors
    ///
    /// Returns [`DoneError::NoSuchLine`] for an ordinal with no `held` line:
    /// the `done` is refused.
    pub fn keep(&mut self, k: u64, at: Option<u64>, minted: Option<&str>) -> Result<Settled, DoneError> {
        let unplaced = self.leave(k, Done::Kept { at }, minted)?;
        Ok(self.settle(unplaced))
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
        let mut unplaced = Vec::new();
        for &k in ks {
            if let Ok(lines) = self.leave(k, done, None) {
                left = true;
                unplaced.extend(lines);
            }
        }
        if left {
            self.settle(unplaced)
        } else {
            Settled::default()
        }
    }

    /// Takes line `k` out of the queue, owing its `done` where it is on disk.
    ///
    /// It is the change every `done` makes ([`HeldQueue::done`],
    /// [`HeldQueue::keep`], [`HeldQueue::done_all`]), before the retry that
    /// writes it: the pieces naming the line's words placed at `minted`, a
    /// kept line's, or their lines' anchors dropped where it names none
    /// ([`Lines::leave`]), and the queue's bytes recounted by them. It
    /// answers the lines whose anchors were dropped.
    ///
    /// # Errors
    ///
    /// Returns [`DoneError::NoSuchLine`] for an ordinal with no `held` line,
    /// the queue as it stood.
    fn leave(&mut self, k: u64, done: Done, minted: Option<&str>) -> Result<Vec<u64>, DoneError> {
        // A line kept at a position raises the lines standing after it on its
        // document to it.
        let kept_at = match done {
            Done::Kept { at } => at,
            Done::Dropped => None,
        };
        let minted = minted.filter(|_| matches!(done, Done::Kept { .. }));
        let (line, placing) = self.lines.leave(k, kept_at, minted).ok_or(DoneError::NoSuchLine)?;
        self.held_bytes = self.held_bytes.saturating_sub(placing.spent).saturating_add(placing.spends);
        // A file never created, or a line waiting for its first copy, holds
        // nothing on disk to resolve; a line on disk owes its `done`, counted
        // until it lands.
        let bytes = line.held_bytes();
        if self.disk.created && self.disk.holds(k) {
            self.disk.owing.get_or_insert_with(Box::default).owed.insert(k, Due::Done { done, bytes, addr: minted.map(str::to_owned) });
        } else {
            self.held_bytes = self.held_bytes.saturating_sub(bytes);
            if let Some(owing) = self.disk.owing.as_mut() {
                owing.first.remove(&k);
            }
            // A parked line's only copy stands on the pending file, which no
            // `done` reaches.
            if let Some(superseded) = self.disk.superseded.as_mut() {
                if superseded.standing.remove(&k) {
                    superseded.left.push(done);
                }
            }
        }
        Ok(placing.unplaced)
    }

    /// Writes the `done`s owed, and compacts the file where no line stands.
    ///
    /// It is the end of every `done` ([`HeldQueue::done`],
    /// [`HeldQueue::keep`], [`HeldQueue::done_all`]): the retry, then the
    /// compaction once the queue holds no line ([`HeldQueue::compact`]).
    /// `unplaced` are the lines whose anchors the leaving dropped, answered
    /// where they stand still.
    fn settle(&mut self, mut unplaced: Vec<u64>) -> Settled {
        self.retry();
        unplaced.retain(|&k| self.lines.contains(k));
        let unremoved = if self.lines.is_empty() { self.compact() } else { None };
        Settled { unremoved, unplaced }
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
    /// ([`HeldQueue::parked`]). `left` is how each line left that the file
    /// holds standing and this queue does not, the `done`s the replaced queue
    /// owed it ([`HeldQueue::dones_owed`]), counted until the file goes
    /// ([`HeldQueue::copies_owed`]). The retry removes the file once no copy
    /// is owed ([`HeldQueue::retry`]), so a crash before then leaves both
    /// files for the next launch's join, which enters no line twice; a
    /// removal the device refuses is kept for the next retry and answered
    /// ([`HeldQueue::superseded`]).
    pub fn supersede(&mut self, pending: PathBuf, standing: BTreeSet<u64>, left: Vec<Done>) {
        self.disk.superseded = Some(Superseded { path: pending, refused: None, standing, left });
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

    /// Returns whether line `k` has no copy on any file: a close loses it.
    ///
    /// A parked line has one, on the pending file ([`HeldQueue::parked`]).
    pub fn off_disk(&self, k: u64) -> bool {
        !self.disk.holds(k) && !self.parked(k)
    }

    /// Returns whether a line standing on `doc` has no copy on any file.
    ///
    /// Every `held` event asks it, so it walks the first copies owed and
    /// `doc`'s ordinals together, each step past an ordinal of either: a
    /// document's cost is its own lines' where they lie among those owed, and
    /// a lookup's where they do not (`Lines`; skep #816).
    pub fn waits_on(&self, doc: &str) -> bool {
        let (Some(owing), Some(on_doc)) = (self.disk.owing.as_deref(), self.lines.ordinals_on(doc)) else { return false };
        let mut from = 0;
        while let Some(&owed) = owing.first.range(from..).next() {
            let Some(&stands) = on_doc.range(owed..).next() else { return false };
            if stands == owed && !self.parked(owed) {
                return true;
            }
            // Ordinals are within `MAX_ORDINAL`, so a successor is a `u64`.
            from = if stands == owed { owed + 1 } else { stands };
        }
        false
    }

    /// Returns what the queue's file still owes its lines ([`CopiesOwed`]).
    ///
    /// A first copy owed a parked line counts nothing, its copy standing on
    /// the pending file; the `done`s are [`HeldQueue::dones_owed`]'s.
    pub fn copies_owed(&self) -> CopiesOwed {
        let lines = self.disk.owing.as_ref().map_or(0, |owing| owing.first.iter().filter(|&&k| !self.parked(k)).count());
        let dones = self.dones_owed();
        let kept = dones.iter().filter(|done| matches!(done, Done::Kept { .. })).count();
        CopiesOwed { lines, kept, dropped: dones.len() - kept }
    }

    /// Returns how each line left whose `done` no file holds.
    ///
    /// They are the `done`s this queue's file owes, and those of the pending
    /// file it took its lines from, while that file stands.
    pub fn dones_owed(&self) -> Vec<Done> {
        let owed = self.disk.owing.iter().flat_map(|owing| owing.owed.values()).filter_map(|due| match due {
            Due::Done { done, .. } => Some(*done),
            Due::Mark => None,
        });
        owed.chain(self.disk.superseded.iter().flat_map(|superseded| superseded.left.iter().copied())).collect()
    }

    /// Returns the ordinals of the standing lines whose first copy is in the
    /// queue's file.
    pub fn standing_on_disk(&self) -> BTreeSet<u64> {
        self.lines.ordinals().filter(|&k| self.disk.holds(k)).collect()
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
        let mut by_carried: HashMap<Carried<'_>, usize> = HashMap::new();
        if fresh.is_some() {
            for here in self.lines.carried() {
                *by_carried.entry(here).or_default() += 1;
            }
        }
        let mut entering = Entering { next_k: fresh, ..Entering::default() };
        // What each line of `from` carries, beside the line as `from` hands
        // it out: both in `k` order.
        for (n, (carries, line)) in from.lines.carried().zip(from.lines.handouts()).enumerate() {
            let repeated = match fresh {
                None => self.lines.contains(line.k),
                Some(_) => by_carried.get_mut(&carries).filter(|count| **count > 0).map(|count| *count -= 1).is_some(),
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
            entering.lines.push(HeldLine { k, ..line });
        }
        entering
    }

    /// Enters `lines`, each under its ordinal and owed its first copy.
    ///
    /// It is the ordered insert, the queue kept in `k` order. None of `lines`
    /// is under an ordinal a standing line holds; each enters after every floor
    /// given here, so no line kept before it raises it, and its pieces bind
    /// as it enters, in `k` order (`Lines`). The queue's bytes count each,
    /// and the greatest ordinal named moves past them.
    fn enter(&mut self, lines: Vec<HeldLine>) {
        if lines.is_empty() {
            return;
        }
        self.greatest_k = lines.iter().fold(self.greatest_k, |greatest, line| greatest.max(line.k));
        self.disk.owing.get_or_insert_with(Box::default).first.extend(lines.iter().map(|line| line.k));
        for line in lines {
            self.held_bytes = self.held_bytes.saturating_add(self.lines.enter(line));
        }
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
        let Some(first_k) = self.lines.first_k() else { return Ok(Vec::new()) };
        let mut k = *next_k;
        let mut moved = Vec::with_capacity(self.lines.len());
        let mut renumbered = Lines::default();
        let mut copy = Vec::new();
        for old in self.lines.ordinals() {
            copy.extend(done_line_bytes(old, Done::Dropped, None));
        }
        for line in self.lines.handouts() {
            let old = line.k;
            let refused = |error: io::Error| RenumberRefused { k: old, error };
            if k > MAX_ORDINAL {
                return Err(refused(io::Error::new(io::ErrorKind::InvalidInput, format!("the ordinal {k} is past the held store's {MAX_ORDINAL}"))));
            }
            let fresh = HeldLine { k, ..line };
            let bytes = held_line_bytes(&fresh, fresh.base);
            if let Some(error) = past_the_line_bound(&bytes) {
                return Err(refused(error));
            }
            copy.extend_from_slice(&bytes);
            renumbered.enter(fresh);
            moved.push((old, k));
            // `k` is within MAX_ORDINAL, so its successor is a `u64`.
            k += 1;
        }
        if let Err(error) = self.disk.ensure_header().and_then(|()| self.disk.append(&copy)) {
            return Err(RenumberRefused { k: first_k, error });
        }
        // The lines under their fresh ordinals, each base as it was handed
        // out: a reader of the file finds the same.
        self.lines = renumbered;
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

/// Returns a `held` line's exact bytes (§3c.2), `base` spelled as its base.
///
/// The base is the caller's to give, so no copy spells a standing line's
/// own base where its document's floor raised it (`Lines::copy`). Its
/// members are `held, doc, id?, base, frame, anchors?, cause,
/// refusal?, sent, time`, in that order — `anchors` as
/// `{"before":<edge>,"after":<edge>}`, each edge an I-address, `null` or a
/// piece `{"burst":<string>,"offset":<natural>}`, on a line whose burst
/// carried them alone, a span they name spelled before its closing brace as
/// `,"span":[{"start":<I-address>,"width":"<natural>"}]`, one object per run.
fn held_line_bytes(l: &HeldLine, base: u64) -> Vec<u8> {
    let mut s = format!("{{\"held\":{},\"doc\":{}", l.k, json_str(&l.doc));
    if let Some(id) = &l.id {
        let _ = write!(s, ",\"id\":{}", json_str(id));
    }
    let _ = write!(s, ",\"base\":{base},\"frame\":{}", l.frame);
    if let Some(anchors) = &l.anchors {
        let anchor = |a: &Option<Anchor>| match a {
            None => "null".to_string(),
            Some(Anchor::Address(addr)) => json_str(addr),
            Some(Anchor::Piece(piece)) => format!("{{\"burst\":{},\"offset\":{}}}", json_str(&piece.burst), piece.offset),
        };
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
/// Its members are `done, as, at?, addr?, time`, in that order — `at` and
/// `addr`, the first I-address a kept insert's words were minted at
/// (skep #969), on a `kept` line alone.
fn done_line_bytes(k: u64, done: Done, addr: Option<&str>) -> Vec<u8> {
    let (resolved, at, addr) = match done {
        Done::Kept { at } => ("kept", at, addr),
        Done::Dropped => ("dropped", None, None),
    };
    let mut s = format!("{{\"done\":{k},\"as\":\"{resolved}\"");
    if let Some(at) = at {
        let _ = write!(s, ",\"at\":{at}");
    }
    if let Some(addr) = addr {
        let _ = write!(s, ",\"addr\":{}", json_str(addr));
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
