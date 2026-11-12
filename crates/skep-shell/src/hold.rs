//! The hold (`client.md` §3c.4, §3c.5).
//!
//! It is the one path of every `/op` the `op` row sends under a session,
//! the per-(board, principal) queue the shell consults on every burst, and
//! the resend walk that drains the queue once the board returns.
//!
//! **One path.** Every `/op` the `op` row sends under a session — `/op-at`'s
//! aside, whose answer is the board's own — goes out by one path,
//! [`Holds::send`]: attested where the session's key attests its kind,
//! dialed, and each answer read once through the classification table
//! ([`classify`]: §3c.4's hold(cause) / unanswered / reissue / neither) — a
//! request the board gave no answer to apart from every answer it gave
//! (`DialError::unanswered`; the board's silence, below) — an ack carried
//! and its `at` noted for the `base` of the next hold on every document it
//! names (§3c.2), and an arrangement write's as the principal's latest one
//! on its document, the editor's own last ack a merge's undo is typed
//! against ([`Holds::last_arranged`]; P3), a later position never lowered
//! by an earlier one read after it — a restore the `history.restore` row
//! made, the library's write and none of this path's, noted so too
//! ([`Holds::note_restored`]) — and entered in the board's acked
//! positions, which the resend's read never takes for a line's lost landing
//! ([`BoardHold::acked`]); a
//! reissue-class answer reissued within the call, a
//! `write_busy` once after [`WRITE_BUSY_WAIT`], a first and second
//! `durability` as-is, so the page meets the ack or the next refusal
//! (§4b.1's `op` row) — the reissue's own `write_busy` and a third
//! `durability` are the table's hold-class answers (§3c.4; skep #786); and
//! anything else faced at the act, save a burst's hold-class answer or
//! refused run, which is held, and a burst the board
//! refuses as typed against an older state of its document
//! (`arrangement_moved`): shifted through the change by the page's anchors
//! and sent again within the call where the span they bound holds the
//! burst's own units still (`resend`'s shift, skep #442, #751), else held
//! as a moved document, the board's verdict kept on its line. The death
//! signal on the session's token, met at the dial, at a read the attest's
//! composer made, or — for a burst refused as typed against an older state —
//! at the shift's read or the moved hold's read of the hands, ends the
//! session, the caller's to run ([`OpAnswer::Died`]): it is neither held nor
//! faced (§3c.4), and never a moved document's verdict, save that a burst
//! which met it is held first, `session_died`, `sent: false` where no dial
//! of it may have landed (the board refuses a dead token's write before it
//! runs the frame, and a stale one before its bounds), so its line, and
//! every later burst of the principal's behind it, stands through the end's
//! reads and goes out under the session that stands next, after its read;
//! the line takes the death's reason once the end derives it
//! ([`Holds::note_death`]). A write the
//! hold never holds is faced where a burst's would be held (§3c.4: "a
//! non-burst write that fails … is faced at its act") — and the nine of
//! them §3c.4 names ([`UNHOLDABLE_WRITES`]; `publication.confirm`'s send,
//! `history.restore`'s write and the merge rows' writes take the list's
//! door under their own ops) meeting a hold that stands at the board before
//! any dial — the own node stopped, the write path poisoned, the writes
//! halted — are REFUSED at once with the hold's cause as the refusal's name
//! ([`Holds::unholdable_refusal`]), never held and never dialed, the page
//! answering before it composes; a board that is unreachable is no such
//! hold, its dial failing as it fails.
//! A write takes that path through THE SHELL's ONE WRITE DOOR
//! (`Shell::write_door`), which asks four questions in one order before any
//! dial and before any read the write makes: a bare session's write is
//! refused (`SessionEntry::may_write`); every write is refused
//! `another_window` where another shell holds the board's store
//! ([`Holds::another_window`], §3c.3), the store touched first for a
//! ceremony, which runs under no session of this shell's
//! ([`Holds::touch_store`]); an unholdable kind is refused under
//! the standing hold ([`Holds::unholdable_refusal`]); and a whole-draft
//! write — the restore's, the merge rows' and the shot — is refused
//! `held_lines` while a line of the principal's stands held on a draft it
//! writes, in any state ([`Holds::held_lines`]; THE HELD-LINES GATE, the
//! held store's shape (vi) item 4) — nothing held there and nothing sent.
//! The hold asks the standing hold's cause once more as a frame reaches
//! [`Holds::send`]: the door's own check behind the shell's, for a follower
//! write sent at its burst's ack and for a hold that came to stand between
//! the door and the dial. And the resend sends under no bare session. A
//! write the session's key
//! owes a signature is never sent without one: where the board's head
//! record, which the signature names, stands and cannot be read, or a
//! claimed board serves none, a burst is held `head_unreadable`, its line
//! carrying the refusal that says why and resent once the record reads, and
//! any other write is refused so, nothing sent (SP-14).
//!
//! **The burst.** A burst is an `op` under a session (never the guest form)
//! whose `frame["op"]` is one of [`BURST_KINDS`] — the burst machine's five
//! — on a draft, as §3c.4 has it, the shell testing the kind alone
//! ([`is_burst`]). It enters by one door, the burst's door,
//! [`Burst::admit`], which refuses at the act a frame the board takes at no
//! send — one past the board's frame cap, one naming no document, an insert
//! a signed session cannot attest — since a held line of it could be sent
//! and resolved never, and would hold every later burst of its principal
//! `behind` it, and an `id` of the prefix the resend's own ids take
//! (`refs::DialId`, `shell:`; skep #971); and it is held without a dial
//! where a hold stands — the own node stopped, the board silent, the board
//! halted, a line of the principal's already held, a request of the hold's
//! at the board unanswered — and, where its own first dial is a request the
//! board gives no answer to, held `unreachable`, no clock started. Its
//! anchors' pieces, each naming the words of a burst of the page's by its
//! `id` (skep #969), are asked under the board's lock past the hold's own
//! door ([`Holds::place_anchors`]): one naming a burst held on the document
//! binds to that line, the burst held `behind` it, and is placed at the
//! address the line's words are minted at as it is kept — its ack's
//! ([`minted_by`]), or the one the resend's read finds — one naming a burst
//! kept there is placed from the principal's newest landed inserts
//! ([`PrincipalHold::landed_inserts`]), and any other is refused at the act.
//! The resend sends each held line through the same reader of an answer,
//! under the line's own dial id in the page's `id`'s place (skep #971): the
//! walk resends every line of a principal's under one session, and the
//! board's retry memo takes a frame for a reissue by its session, its `id`
//! and its kind. A reissue-class answer there is reissued at the next probe;
//! a line no landing of which is found [`HAND_OVER_DEADLINE`] after its
//! first failed send, whatever the failure, is handed to the person, a
//! refused run under `answers_lost` — whose drop, where a dial of it may
//! have landed, reads for its landing first and drops nothing the board is
//! found to hold, nor anything where the read cannot tell
//! ([`Holds::resolve`]; skep #866) — and one the board refuses at a resend
//! under a code the table holds nowhere is handed over at once, a refused
//! run under the board's token (§3c.4). The anchors a burst carries over
//! the bridge (`held::Anchors`) ride with its line and never with its frame:
//! the frame dialed is the wire's frame, as the attest is stripped at the
//! hold and composed at every send, and a resend's `id` is set on the copy
//! it dials alone, the line's frame keeping the page's.
//!
//! **The board's silence** (§3c.4's THE END, §3c.5; skep #863). The probe is
//! the one judge of whether a board answers: a `/health` it gives no answer to
//! — the probe's, the feed thread's, the page's `probe()` and `health(board)` —
//! is its silence, and any answer to one, a refusal among them, is the board
//! answering ([`Holds::note_health_read`]). A request of the hold's the board
//! gives no answer to — a burst's first dial, a resend's read, send, shift read
//! or read of the hands, a drop's, an entry's, a keep's, a landing's or the
//! held list's read of the hands, the probe's read of the board's head — marks
//! the board unanswered until that verdict:
//! nothing more of the hold's is dialed there, a burst is held at once, and a
//! send the request cut is owed to the verdict, a failed send of its line where
//! the verdict finds the board answering — the line's own failure — and none
//! where it finds it silent (`Answering`). A line's two minutes
//! ([`HAND_OVER_DEADLINE`]) run on the board's answering clock: paused across a
//! silence, from the first request it gave no answer to until a `/health`
//! answers, kept and never reset. A read whose answer would set a face sets
//! none where it goes unanswered: a shift's read leaves the shift untried, its
//! verdict kept, and a moved face whose hands' read goes unanswered names them
//! not read (`Hand`), read again at the board's answer for every session told
//! or listed so.
//!
//! **The hands a moved face names** (§3c.5, §4b.2; skep #973, #989). Every
//! face that tells a session a document stands moved — a `held` event, or each
//! moved row of the document's lines in `held(session)` ([`Holds::lines`]) —
//! names the hands of the verdict the document stands on now, read for that
//! session; or the one hand `unread`, owed to the walk, which reads them
//! again; or the one hand `unknowable`, where the board has reclaimed the
//! history the read asks for, which no read can name and none is owed. A
//! burst the board refuses again with no row since the person's `send` names
//! again the hands the face that `send` acknowledged named, marked `again`
//! ([`Holds::hands_since_typed_state`]). The session's memory keeps beside
//! each `moved` face the verdict its hands were read for ([`Judged`]): a face
//! for another verdict is no face of the document as it stands, so the hands
//! are read again and never repeated. The held list reads the hands of each
//! moved document its session's memory holds none for, once the board's lock
//! is let go, and enters what its rows name in that memory, saying no event.
//!
//! **The state that stays in front** (§4b.2; skep #974). While a document's
//! first line awaits the person's act — a refused run's or a moved
//! document's, no send having it out for its dials
//! ([`PrincipalHold::first_awaiting_act`]) — every `held` event for the
//! document says that line's state, as a person's act says what stands
//! ([`Holds::say_standing`]): a burst held behind it, a line kept or told
//! behind it, and a landing all say it, the lines behind it changing the
//! count alone, and the hands it owes are read once the board's lock is let
//! go. The `held` answer names the burst's own cause.
//!
//! **The board's state** (§3c.3, §4b.2; P37; skep #865). The page is told what
//! stands at a board before a write meets it: one state, the most severe that
//! holds — the own node stopped, the board silent, its writes halted, its
//! head record not reading, in that order, else running ([`BoardState`]) —
//! derived from what the hold already keeps ([`BoardHold::state`]). Each
//! change since the state last told is taken once ([`Holds::state_change`]),
//! by the board's feed thread alone, which says it on the `daemon` event, and
//! `probe()` answers the state as it stands ([`Holds::state`]). Every read of
//! the board's head feeds it, wherever it is made ([`Holds::note_head`]).
//!
//! **The store, from the first touch** (§3c.1, §3c.3; skep #857, #858,
//! #859, #873, #880). A board's held store is taken at its first touch: a
//! session's open or a ceremony's door, each the store's touch
//! ([`Holds::touch_store`]), which reads the board's head once and
//! establishes the store from whatever it answers, or a probe, whose retry
//! tries the locks without a read. The PENDING directory,
//! `held/pending/<hash of the origin dialed>/`, is made and locked always,
//! and where the head names a term the board's own directory,
//! `held/<chain>/`, is made and locked after it, the pending lock first
//! (skep #828). Both locks are kept for the shell's life
//! ([`Directory::ThisWindow`]); a shell that finds either held takes none —
//! it lets go any it took in that try, opens no file, and stands another
//! shell's ([`Directory::AnotherWindow`]): ONE SHELL PER DATA DIRECTORY
//! (§3c.3), a second launch hands its address to the running client and
//! exits, and until that hand-off stands this shell reads alone at the
//! board, one writer per board — every write refused `another_window` at
//! the door before any dial ([`Holds::another_window`]), nothing held and
//! nothing sent, the lines held before the state was found sent as the
//! board takes them — and tries both locks again at every probe and at
//! every touch, taking both once both are free, each edge of the state said
//! once in the shell's own window and emitted once as `another-window`
//! (skep #827). A ceremony runs under no session of this shell's, so its
//! door takes the touch itself before it answers (`Shell::write_door`): a
//! shell that has opened no session at the board meets the board's locks
//! as they stand. The one other standing is a device's refusal of the
//! pending directory or its lock ([`Directory::NotYet`]), tried again at
//! every copy, every probe and every touch.
//!
//! **The queue** is each principal's [`HeldQueue`], in `k` order across the
//! board's documents, and every line of it goes to disk from the
//! principal's first touch: its file is the board's own,
//! `held/<chain>/principal-<n>.held`, where the board's own directory is
//! this shell's, else the pending one, `held/pending/<hash>/principal-<n>.held`
//! — the board's head record standing and not reading, a claimed board
//! serving none, the board away or unclaimed at the first touch (§3c.1;
//! skep #725) — each line written there and synced before `op` answers
//! `held`. The file is opened — read, P38's faces kept — at the principal's
//! first touch, under a session as its principal (P39), by the principal's
//! door, [`Holds::principal_hold`], which every act on a principal's queue
//! takes, a burst's among them once the burst's door has let it in; where
//! the board's own directory is this shell's then, an earlier run's pending
//! file is opened beside it and its lines join the board's file under fresh
//! ordinals (`held`'s join). A halted file — the pending one, or the
//! board's — halts the principal before any hold: the door answers every
//! act `store_halted` with the halt's `why` alone, the file's path the
//! native side's — [`Holds::halted_file`] reads it, and
//! [`Holds::show_halted`] shows it in the shell's own window as often as the
//! page's `held.show` asks — crossing the bridge never (§3c.3, §4b.3).
//! THE PENDING → CHAIN CHANGE: once the board's own directory is this
//! shell's — a term read at a later probe or open — each queue on a pending
//! file opens the board's file, which could not be named before (an earlier
//! run's lines in it renumbered past this run's, `HeldQueue::renumber`; skep
//! #875), and every line of this run's becomes a copy OWED to it, written by
//! the one retry as one copy with one sync, one by one where the device
//! refuses it, what lands kept (skep #859); the pending file is removed once
//! no copy is owed, and a crash before then leaves both files for the next
//! launch, whose join enters no line twice. A halt found at the change
//! halts the principal from that moment, the pending file left as it stands
//! (skep #858). Wherever a principal's lines are, their ordinals are one
//! space for the shell's life ([`PrincipalHold::next_k`]; skep #856): the
//! change moves no ordinal a call or the page holds.
//! THE ONE MEMORY CASE is a device's refusal (§3c.3; skep #813, #821): a
//! copy the device refuses — a line's first, or a re-mark's, a raise's, a
//! shift's or a `done`'s of a line on disk — is owed, and waits in memory
//! with every copy owed after it, none written ahead of it, until the retry
//! writes them in `k` order (`HeldQueue::retry`) — before the queue's next
//! copy, and at every probe whatever the board's state; and where the
//! device refuses the store itself — the pending directory or its lock at
//! the first touch, the file's read at the door, or the renumbering copy
//! the read owed — the queue still names its file, not yet read, every line
//! held meanwhile owed to it, and the retry makes the directory, takes its
//! lock, reads the file and makes the renumbering copy, in that order,
//! before it writes a line ([`Holds::retry_store`]); or, finding the lock
//! held, the shell stands another shell's, the lines held before that was
//! found sent from memory as the board takes them (skep #789). Each answer
//! for a line waiting for its first copy carries the refusal as
//! `unwritable`, the wait is said in the shell's own window once as it
//! begins and once as it ends ([`Holds::note_waiting`]), a close while a
//! copy is owed loses it, and a relaunch reads each line as the file last
//! held it. The probe ([`Holds::probe`]) and the resend it lets run, which
//! drain the queue once the board returns in turns of at most
//! [`TURN_STEPS`] steps, the feed thread serving the work queued behind each
//! turn before the next ([`Turn`]), are the child module `resend`'s: one
//! read of the board's head per probe decides the directory and which
//! documents are skipped ([`Holds::establish`]).
//!
//! **Why a line stands off disk** rides its `held` answer ([`Unwritable`];
//! §3c.3; skep #820): `unwritable`, the words — the device's refusal of the
//! line's copy, or of the store: the directory, its lock, the file's read —
//! and `unwritable_class` beside them, read off the refusal's kind alone,
//! never its words, which differ by platform ([`UnwritableClass`]): `full`
//! (a full device, a spent quota), `read_only` (a read-only volume, a write
//! the shell has no right to make) or `other` (every other kind), so the
//! page keys its act by cause (§3c.3's face): space freed ends a `full`
//! refusal, the retry then writing the line, and none ends a `read_only`
//! one. A line waiting behind a refused copy carries that copy's refusal
//! unchanged. The `held` row carries the two members while its line stands
//! on no file, and the `held` event while a line of its document does
//! (`HeldQueue::off_disk`, `HeldQueue::waits_on`; skep #860): a line parked
//! on the pending file has a copy a close keeps, and carries neither. The
//! probe says each document whose lines the retry has written, the event
//! repeating what it last told but for the two members
//! ([`Holds::say_landed`]), so the page's face lifts as the copy lands; a
//! session told no face of a document that stands moved, or another move's,
//! hears it with the hands of the verdict it stands on, read once the board's
//! lock is let go, or named not read (skep #972, #973). What
//! a close leaves owed is the native side's read ([`Holds::copies_owed`]),
//! a line whose `done` is owed staying off the rows, which list the queue.
//!
//! **Each board's hold its own lock**, the boards fixed at the open: a
//! board's appends, each synced to disk, its file's read at a session's open
//! and its resend's bookkeeping hold that board's lock alone, so no board's
//! wait is another's.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_client::board::{acked_addr, acked_at, Answer, Board, ChangesAnswer, ChangesQuery, Health, Rejection};
use skep_client::halt::Halt;
use skep_client::history::Restored;
use skep_client::sheet::render_inert;
use skep_client::store::{FileStore, KeyFacts};
use skep_client::{DialError, Origin};
use skep_search::Chain;

use crate::attest::{attest_room, insert_terms, Unattested};
use crate::events::{EventBus, EventName};
use crate::held::{
    i_address, Anchor, Anchors, CopiesOwed, Done, Entered, HaltWhy, HeldDir, HeldLine, HeldQueue, Joined, Joining, Opened, Owed, Reason, RenumberRefused, Settled, Torn, Unheld, MAX_BURST_ID_BYTES,
    MAX_HELD_BYTES, MAX_HELD_LINES,
};
use crate::refs::{BoardEntry, DialId, DIAL_ID_ROOM};
use crate::refusal::{Name, Refusal};
use crate::sessions::{board_head, HeadRead, SessionEntry, Sessions};
use crate::wire::{document_address, json_len, values_of, MAX_FRAME_BYTES};
use crate::Talk;

mod labels;
mod resend;

use labels::AccountLabels;
use resend::{Dialing, ReadOutcome};

/// The interim probe cadence (§3c.4): `GET /health` at this interval.
///
/// The probe reads it while a session that may write stands at a board, so
/// a board whose writes halt or whose head record will not read is found with
/// no line held (skep #865); while a burst is held there; while its writes
/// stand halted or its head unreadable, so a state told clears with no
/// session left; and while the board is silent or a request of the hold's
/// there unanswered, so the verdict that ends the silence comes with no line
/// standing; the value is open to tuning. It is the retry's clock too
/// (§3c.3), whatever the board's state, so space freed while no one types is
/// enough: a store the device refused is made and locked again, a file it
/// refused read, and a copy it refused — a line's, a re-mark's or a `done`'s
/// — written again at every probe while it is owed ([`Holds::retry_store`]);
/// and the locks another shell held are tried again. A drain whose turn stops
/// at its bound is no cadence's: the feed thread runs its next turn once the
/// work queued behind it is served ([`Turn::Bounded`]).
pub const PROBE_CADENCE: Duration = Duration::from_secs(2);

/// The most steps one turn of a drain takes (§3c.5; skep #817, #862).
///
/// A step is a document's read for its head's own landing, a line's send,
/// a shift of a line the board refused as typed against an older state, its
/// image read and its shifted dial, a moved document's test of that shift
/// (`resend`'s `test_shift`), or a moved document's read of the hands its
/// faces named not read (`resend`'s `reread_hands`): each a dial of the
/// board — the shift's two, the read of the hands one under each session
/// owed them, or two where a burst refused again reads from the face the
/// person's `send` acknowledged — in the order the walk meets them
/// (`resend`'s turns). The bound is what lets the board's feed thread serve
/// the work queued behind a drain — a `search`, a listing, a session's swap —
/// before the drain goes on: 64 sends at some 13 ms each, a line's mark and
/// its `done` synced beside its dial (`held::MAX_HELD_LINES` states the
/// figure), keep a turn under a second, so that work waits under a second,
/// and a full queue drains in 256 turns, each one `/health` read and one
/// read of the board's head more than one turn would make.
pub(crate) const TURN_STEPS: usize = 64;

/// What one probe's turn of the drain left (`Holds::probe`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Turn {
    /// The turn stopped at its bound ([`TURN_STEPS`]) with a line still to
    /// send: the drain's pass goes on at the next turn, which the feed thread
    /// runs once the commands queued behind this one are served.
    Bounded,
    /// The board gave a request of the turn's no answer (§3c.5; skep #863).
    ///
    /// The request is its `/health`, the read of its head, or one the walk
    /// made.
    ///
    /// The pass ends there and waits for the next probe at the cadence, which
    /// goes on with the documents the pass did not reach, the one the silence
    /// cut last.
    Unanswered,
    /// No turn stopped at its bound, and the next probe comes at the cadence.
    ///
    /// The pass walked every line it could send, or no drain ran — no probe
    /// owed the board ([`BoardHold::probe_owed`]), the own node stopped, the
    /// board's `/health` refused, refused before any connection or read with
    /// its writes halted, or another drain of the board running.
    Done,
}

/// What one `/health` read told the hold of its board (§3c.4's THE END).
///
/// It is [`Holds::note_health_read`]'s answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The board gave the read no answer: its silence.
    Silent,
    /// The read was refused before any connection opened: it reached no board.
    ///
    /// It is a board whose scheme this build does not hold
    /// (`DialError::NotHeld`). It tells nothing of the board: neither its
    /// silence nor its answer, and the hold stands as it stood, so a burst
    /// there is dialed and faced as built, never held where no probe could
    /// send it.
    Undialed,
    /// The board answered and takes no write now.
    ///
    /// Its `/health` was refused, or read with its writes halted.
    Holds,
    /// The board answered its `/health`, and its writes go.
    Writes,
}

/// A held line's deadline: two minutes of the board answering.
///
/// It is one per line, run from the line's first failed send, whatever the
/// failure (§3c.4; skep #716, #720, #722): a send fails where its dial left,
/// or was answered, and did not land — a lost answer (a garbled answer, the
/// board's handler panicking), a `poisoned` answer, a reissue-class answer
/// at its count, a `durability` hold, a refusal the table holds nowhere, the
/// board's refusal of a burst typed against an older state, shifted or not —
/// the person's own first dial among them; a connection never made starts
/// nothing, the board being away, and nor does a request refused before any
/// connection, an attest that could not be composed, or the death signal,
/// which is neither — the line it holds waits for a session, not for the
/// board ([`failed_send`], [`Dialed::failure`]). A send the board gave no
/// answer to once connected — a timeout, a connection closed before any
/// answer — is a failed send where the next `/health` finds the board
/// answering, at the send's own instant, and none where it finds the board
/// silent (`Answering`). The two minutes run on the board's answering clock
/// alone (skep #863): across a silence, from the first request the board
/// gave no answer to until a `/health` answers, no line's count runs, a
/// count already running paused and kept, never reset
/// (`BoardHold::answering_at`). At the deadline the next read that finds no
/// landing of the line hands it to the person as a refused run,
/// `answers_lost`, naming the last failure and the wall time since its first
/// failed send, its `sent` kept and the lines behind it waiting with it
/// (§3c.5); a read that finds its landing keeps it, so the hand-over never
/// sends it twice, and the person's drop of a `sent` line reads for its
/// landing again before it drops anything ([`Holds::resolve`]; skep #866),
/// since a write whose answer was lost can land after the hand-over's read.
/// A code the table holds nowhere is handed over at once,
/// since it cannot resolve; a shift is refused past the deadline, so the
/// clock bounds the shifts a document another writer keeps moving asks of a
/// line, a turn of the resend making at most its steps of them
/// ([`TURN_STEPS`]) and leaving the line for the drain's next pass, whose
/// read hands it over once the deadline has passed; and the resend's "sent
/// again" is said once per change of the failure. The clock is in memory,
/// per line, so a relaunch starts it afresh, as the person's `send` does.
pub(crate) const HAND_OVER_DEADLINE: Duration = Duration::from_secs(120);

/// The short wait before a `write_busy` is reissued.
///
/// It is §3c.4's "a silent reissue after a short wait" — interim, open to
/// tuning, as [`PROBE_CADENCE`] is.
const WRITE_BUSY_WAIT: Duration = Duration::from_millis(50);

/// The burst machine's five kinds (§3c.4) — the ops the held store holds.
const BURST_KINDS: [&str; 5] = ["insert", "delete", "copy", "reinstate", "rearrange"];

/// The nine non-burst writes §3c.4 names, which a standing hold refuses.
///
/// Each arriving while the board is stopped, poisoned or its writes halted
/// is refused at once with the hold's cause as its token, never held and
/// never dialed ([`Holds::unholdable_refusal`], the shell's one write
/// door's third question); `publication.confirm`'s send, the shot's one
/// carrier, and `merge.land`'s, which rides it, take the door with `publish`
/// as their op; `stage`, the staging act's mint (B3-S10), takes it as `fork`
/// does, and a `merge.compose` that stages a fresh draft takes it under
/// that op; `set_arrangement`, a draft's whole arrangement set in one write
/// (the landing lane, skep #764), takes it too — no burst, since it is the
/// landing of a merge and no act of the page's hand, and a landing held
/// would land over whatever the hand wrote meanwhile — and the restore's
/// write, `history.restore`'s, the undo's and the withdrawal's take it as
/// `set_arrangement`; `create_new_document`, the mint, takes it since it
/// cannot be held either — the page needs the new document's address before
/// it can type into it — and dialed under a stopped node it failed
/// `unreachable`, a network fault's face for a notebook its owner stopped
/// (skep #868). Every other write outside the five bursts dials as it dials.
pub const UNHOLDABLE_WRITES: [&str; 9] =
    ["create_new_document", "fork", "version", "stage", "set_arrangement", "make_link", "nullify", "edit_link", "publish"];

/// Returns whether `frame` is a burst: one of the five kinds.
///
/// §3c.4 says "on a draft under the session" — the kind test is the
/// shell's; a write on a document that is no draft is the board's refusal,
/// permanent, and so a refused run. The `op` row's table of the bursts a
/// follower may follow asks it too (`shell/follow.rs`).
pub(crate) fn is_burst(frame: &Value) -> bool {
    frame["op"].as_str().is_some_and(|op| BURST_KINDS.contains(&op))
}

/// §3c.2's causes, as a held line and its answer spell them.
///
/// Beside these, the shell's own `head_unreadable` holds a signed write
/// whose signature could not be made, its own `session_died` a burst whose
/// dial met the death signal, and a refused run's line carries the
/// board's own token, or the shell's `answers_lost` where it handed the
/// person a line no landing of which was found at its deadline
/// ([`HAND_OVER_DEADLINE`]), its verdict beside it. A line the board refused
/// as typed against an older state of its document (`arrangement_moved`)
/// that the shift could not move through the change exactly — no anchors, a
/// delete or a rearrange without its span, an anchor lost or at two places,
/// the span between them cut or refilled, the read refused, or the line's
/// deadline passed — carries `moved`, and the board's verdict beside it as a
/// refused run's does; a line the shift moved and sent again keeps the cause
/// it had.
mod cause {
    pub const UNREACHABLE: &str = "unreachable";
    pub const STOPPED: &str = "stopped";
    pub const POISONED: &str = "poisoned";
    pub const HALTED: &str = "halted";
    pub const DURABILITY: &str = "durability";
    pub const BEHIND: &str = "behind";
    pub const MOVED: &str = "moved";
    /// A signed write held for want of its signature.
    ///
    /// The board's head record (`H.1`), which the signature names, stands and
    /// cannot be read, or a claimed board serves none (SP-14); the line holds,
    /// its refusal saying why, until the record reads again.
    pub const HEAD_UNREADABLE: &str = "head_unreadable";
    /// A burst held at the death signal on its session's token (§3c.4).
    ///
    /// The signal was met at the burst's first dial, at a read its attest's
    /// composer made, or — the board having refused the burst as typed
    /// against an older state — at the shift's read, the shifted dial, or the
    /// moved hold's read of the hands. The line holds, `sent: false` where no
    /// dial of it may have landed and the shift's mark kept where a shifted
    /// dial left, until a session of the principal's that may write stands —
    /// the restart arm's re-open among them — which resends it after its
    /// read. Once the session's end derives the death, the line's refusal is
    /// the `session_died` refusal with the death's reason beside it (§4b.2's
    /// arms, the retired arm's `own` among its members), so the page faces a
    /// line that no re-open of this device's key will send.
    pub const SESSION_DIED: &str = "session_died";
}

/// A hand whose row moved a held document (§3c.5; §4b.2's `held` event).
///
/// Each is read off a `/changes` row since the burst's typed state, or since
/// the position the person's last `send` on the document acknowledged the
/// rows through where that is later, where the board refused it as typed
/// against an older state — the one route to a moved document; the resend's
/// read judges no move: this store's own key, another key with its label —
/// this shell's key store's where it holds that key, else the one the
/// account's verified records give it (`labels`; skep #869) — an unsigned
/// hand under local trust, or a row whose testimony the board lost — the
/// data of the three forms the moved face draws, the strings the copy's.
/// Where no page of the rows named them — the board gave the read no answer
/// or answered it with no page, the read met the death signal, or none was
/// made — the one hand is `unread`: the hands not read yet, apart from a
/// hand lost, read again for every session told or listed so (§3c.5's THE
/// SHIFT (6); skep #863, #972, #973). Where the board has reclaimed the
/// history the read asks for, so that no read can ever name them, the one
/// hand is `unknowable`, owed to no read (skep #989).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hand {
    /// `own`, `other`, `bare`, `lost`, `unread` or `unknowable`.
    pub key: &'static str,
    /// The key's fingerprint, for `own` and `other`.
    pub fingerprint: Option<String>,
    /// The label of an `other` key, rendered inert.
    ///
    /// It is this shell's key store's where the store holds the key, else
    /// the one the account's verified records give it; absent where neither
    /// names one.
    pub label: Option<String>,
}

impl Hand {
    /// The hands of a moved document no page of the rows has named yet.
    const UNREAD: Hand = Hand { key: "unread", fingerprint: None, label: None };

    /// The hands of a moved document whose rows the board has reclaimed.
    ///
    /// No read can name them: the board's floor never moves down.
    const UNKNOWABLE: Hand = Hand { key: "unknowable", fingerprint: None, label: None };

    /// Returns the hand as the `held` event carries it.
    fn json(&self) -> Value {
        let mut v = json!({"key": self.key});
        if let Some(fp) = &self.fingerprint {
            v["fingerprint"] = Value::from(fp.as_str());
        }
        if let Some(label) = &self.label {
            v["label"] = Value::from(label.as_str());
        }
        v
    }
}

/// What the moved hold's read of the hands answered (§3c.5).
///
/// It is the hands, the board's silence, an answer with no page, a history
/// the board has reclaimed, or the death signal on the session's token, whose
/// end is the caller's to run (§3c.4) — no verdict on the document, so the
/// burst is held at the death and never faced moved
/// ([`Holds::hands_since_typed_state`]).
#[derive(Debug)]
enum HandsRead {
    /// The hands whose rows moved the document, each once.
    ///
    /// They are none where the page holds no row, or no read was owed.
    /// `again` is whether no row has landed since the person's last `send`
    /// on the document, the hands read from where the face that `send`
    /// acknowledged read them (skep #989).
    Named { hands: Vec<Hand>, again: bool },
    /// The board gave the read no answer (skep #863).
    ///
    /// The moved face stands on the board's verdict, its hands named not
    /// read ([`Hand::UNREAD`]) and read again at the board's answer.
    Unanswered,
    /// The board answered the read with no page (skep #972).
    ///
    /// It is a refusal, or an answer no read takes. The moved face names its
    /// hands not read ([`Hand::UNREAD`]), read again as the walk meets the
    /// document, the board answering all the same.
    Unread,
    /// The board has reclaimed the history the read asks for (skep #989).
    ///
    /// It answered `history_reclaimed`, its floor past the read's position,
    /// and the floor never moves down: the moved face names its hands
    /// `unknowable` ([`Hand::UNKNOWABLE`]), and no read is owed for them.
    Unknowable,
    /// The death signal on the session's token.
    Died,
}

impl HandsRead {
    /// Returns what a moved face names of the read ([`HandsFace`]).
    ///
    /// The hands are the one hand `unread` wherever no page named them and a
    /// later read may (§3c.5; SP-14; skep #972), the face saying they are not
    /// read yet, and the one hand `unknowable` where no read can (skep #989).
    /// It answers none at the death signal, which each caller meets as the
    /// death at its dial.
    fn face(self) -> Option<HandsFace> {
        match self {
            HandsRead::Named { hands, again } => Some(HandsFace { hands, again, unanswered: false }),
            HandsRead::Unanswered => Some(HandsFace { unanswered: true, ..HandsFace::not_read() }),
            HandsRead::Unread => Some(HandsFace::not_read()),
            HandsRead::Unknowable => Some(HandsFace { hands: vec![Hand::UNKNOWABLE], again: false, unanswered: false }),
            HandsRead::Died => None,
        }
    }
}

/// What a moved face names of one read of its hands (§3c.5).
///
/// It is the hands, whether they are again those the face the person's last
/// `send` acknowledged named (`again`; skep #989), and whether the board gave
/// the read no answer, which marks the board unanswered (skep #863). The
/// default names no hand.
#[derive(Debug, Default)]
struct HandsFace {
    hands: Vec<Hand>,
    again: bool,
    unanswered: bool,
}

impl HandsFace {
    /// Returns the face of hands no page has named yet: the one hand `unread`.
    fn not_read() -> HandsFace {
        HandsFace { hands: vec![Hand::UNREAD], again: false, unanswered: false }
    }
}

/// What a `moved` event says beside its state (§3c.5; §4b.2's `held` event).
///
/// It is the hands whose rows moved the document; `again`, whether those are
/// the hands the face the person's last `send` acknowledged named, no row
/// having landed since (skep #989); `sendable`, whether a `send` would now
/// shift the document's first moved line, where the shell knows ([`Tested`]);
/// and `judged`, the verdict the hands were read for, which the session's
/// memory keeps beside them ([`HeldSaid`]; skep #973). The default says none
/// of them, as every other state's event does.
#[derive(Debug, Clone, Copy, Default)]
struct MovedFace<'h> {
    hands: &'h [Hand],
    again: bool,
    sendable: Option<bool>,
    judged: Option<&'h Judged>,
}

/// The board's verdict a moved face's hands are read for (§3c.5; skep #973).
///
/// It is the line the board refused as typed against an older state of its
/// document, by its ordinal, and the `arrangement_moved` the line carries,
/// whose typed state the hands are read since ([`typed_state`]). A session's
/// memory keeps it beside the `moved` face it was told ([`HeldSaid`]): a
/// face told for another verdict names no hand of the document as it stands
/// now, and its hands are read again ([`Holds::hands_owed_to`]).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Judged {
    k: u64,
    verdict: Value,
}

impl Judged {
    /// Returns the verdict line `k`, held for `reason`, carries.
    ///
    /// It answers none where `reason` is no `moved` one carrying a verdict
    /// whose typed state reads ([`typed_state`]): no read names hands for it.
    fn of(k: u64, reason: &Reason) -> Option<Judged> {
        typed_state(reason)?;
        Some(Judged { k, verdict: reason.refusal.clone()? })
    }
}

/// A held line that left the store kept, as the `held` event names it.
///
/// It is how the page learns the ack of a line the shell sent after its `op`
/// answered `held` (§4b.2's `held` event; skep #968): the line's ordinal,
/// the one the `held` answer named; the envelope `id` its frame carried,
/// where the page sent one (A-60); the position the board took it at, its
/// ack's `at` (A-62, A-63) or the one the resend's read found it landed at,
/// none where the read found it under a reclaimed history; and the first
/// I-address an insert's `ack_addr` minted (A-63), none for the other kinds
/// and for a landing the read found, which no ack names.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LandedLine {
    k: u64,
    burst: Option<String>,
    at: Option<u64>,
    addr: Option<String>,
}

impl LandedLine {
    /// Returns `line`'s entry, kept at `at`, `addr` the I-address it minted.
    fn of(line: &HeldLine, at: Option<u64>, addr: Option<&str>) -> LandedLine {
        LandedLine { k: line.k, burst: line.id.clone(), at, addr: addr.map(str::to_owned) }
    }

    /// Returns the entry as the `held` event's `landed` carries it.
    fn json(&self) -> Value {
        let mut v = json!({"held": self.k});
        if let Some(burst) = &self.burst {
            v["burst"] = Value::from(burst.as_str());
        }
        if let Some(at) = self.at {
            v["at"] = Value::from(at);
        }
        if let Some(addr) = &self.addr {
            v["addr"] = Value::from(addr.as_str());
        }
        v
    }
}

/// A `held` event a moved face owes, its hands not yet read.
///
/// It is owed where `doc` stands moved on the board's verdict and the last
/// face told the session of it is no `moved` face for that verdict
/// ([`Holds::hands_owed_to`]): the session re-opened since, another of the
/// principal's, told the document's face before the walk under another
/// session held it moved, or told an earlier move's hands (skep #973).
/// [`Holds::say_standing`] answers it, under the board's lock, for a person's
/// act (skep #960) and for a line entered or kept behind the line the
/// verdict rides (skep #974), and [`Holds::say_landed`] for a landing the
/// store's retry wrote (skep #972). `k` and `reason` are the head line the
/// verdict rides as it stood, and `landed` the line the act kept, where it
/// kept one. [`Holds::say_with_hands`] says it once the lock is let go, the
/// hands read first.
#[must_use = "an owed `held` event is said by `Holds::say_with_hands` once the board's lock is let go"]
#[derive(Debug)]
struct HandsOwed {
    doc: String,
    k: u64,
    reason: Reason,
    landed: Option<LandedLine>,
}

/// What the shift test answered of a moved line's `send` (§3c.5; skep #867).
///
/// The test runs the shift a `send` would run against the document as it
/// stands (`resend`'s `test_shift`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tested {
    /// The test ran: a `send` would shift the line into the text as it now
    /// stands (true), or hold it moved again (false).
    Sendable(bool),
    /// No read answered: the image read went unanswered or was refused.
    Unknown,
}

impl Tested {
    /// Returns the `sendable` member a row and an event carry, absent where
    /// the shell does not know.
    fn sendable(self) -> Option<bool> {
        match self {
            Tested::Sendable(sendable) => Some(sendable),
            Tested::Unknown => None,
        }
    }

    /// Returns whether the answer holds the page's "send again" live.
    ///
    /// The page holds the act inert on false and on absent alike (§3c.5).
    fn live(self) -> bool {
        self == Tested::Sendable(true)
    }
}

/// A moved document's shift test as it stands.
///
/// It is its entry in `PrincipalHold::shift_tests`, of the document's head.
#[derive(Debug, Clone, Copy)]
struct ShiftTest {
    /// The ordinal of the line tested, the document's head.
    k: u64,
    /// What the test last answered.
    answer: Tested,
    /// Whether another test is owed: a row has named the document since
    /// ([`Holds::note_rows`]), or the board gave the read no answer.
    stale: bool,
    /// Whether the last `moved` event held the page's act live.
    told: bool,
}

/// The documents a read of the drafts feed named (§3c.5; skep #867).
///
/// It is what a moved document's shift test goes stale by
/// ([`Holds::note_rows`]). A row whose testimony the board lost names no
/// document, and may be the write that changed any of them (wire.md
/// §`/changes`), so it names them all.
#[derive(Debug, Default)]
pub(crate) struct RowsNamed {
    docs: HashSet<String>,
    every: bool,
}

impl RowsNamed {
    /// Notes the documents a `/changes` row names.
    pub(crate) fn note(&mut self, row: &Value) {
        match row["docs"].as_array() {
            Some(docs) => self.docs.extend(docs.iter().filter_map(Value::as_str).map(str::to_owned)),
            None => self.every = true,
        }
    }

    /// Returns whether a row named `doc`.
    fn names(&self, doc: &str) -> bool {
        self.every || self.docs.contains(doc)
    }

    /// Returns whether no row named any document.
    fn is_empty(&self) -> bool {
        !self.every && self.docs.is_empty()
    }
}

/// What a write's dial answered that [`classify`] reads (§3c.4).
///
/// The own node stopped (no dial), an ack and the death signal are not
/// here: a stop holds a burst before any dial, an ack is carried as any
/// `op`'s, and the death signal ends the session, a burst that met it held
/// `session_died` first ([`Holds::send_burst`]). A write the hold never
/// holds is read here as a burst is, and faced where a burst's answer would
/// be held.
#[derive(Debug, Clone, Copy)]
enum DialOutcome<'a> {
    /// The dial failed at the transport.
    Dial(&'a DialError),
    /// The board refused: its code and the `disposition` the body rode.
    ///
    /// The code is a `rejected` document's key, or a non-200's error.
    Rejected { code: &'a str, disposition: &'a str },
}

/// What the shell does with a write's outcome (§3c.4's table).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Decision {
    /// The write held with this cause: a burst's line.
    ///
    /// A write the hold never holds faces it. `sent` is whether the write may
    /// have landed (§3c.2): a dial made whose answer was lost, the board's
    /// `500 internal_panic` among them, or a `poisoned` answer, whose frames
    /// the board's journal keeps for its restart.
    Hold { cause: &'static str, sent: bool },
    /// The board gave the write no answer (§3c.5's five cases; skep #863).
    ///
    /// Its name unresolved, a connection never made, a handshake not
    /// completed (`sent` false: no byte of it left), no answer within the
    /// bound once connected, or the connection closed before any answer
    /// (`sent` true: it may have landed) — `DialError::unanswered`. A
    /// burst is held `unreachable`, the board marked unanswered until the
    /// next probe's verdict; a write the hold never holds faces it.
    Unanswered { sent: bool },
    /// A refused run: a `permanent` or `reorder` refusal.
    ///
    /// Where the write is a burst, it is held with the board's token for its
    /// cause and its verdict beside it.
    Refused,
    /// The board refused the burst as typed against an older state.
    ///
    /// It is an older state of the document's arrangement
    /// (`arrangement_moved`): the burst is shifted through the change and
    /// sent again where its anchors stand at one place each with the span's
    /// own units between them (`resend`'s shift), else held as a moved
    /// document, the verdict kept on the line.
    Moved,
    /// A silent reissue of this kind.
    ///
    /// It comes within the write's call; on a resend, at the next probe.
    Reissue(Reissue),
    /// Neither held nor reissued: faced at its act.
    Neither,
}

/// A reissue-class refusal (§3c.4's reissue row).
///
/// Its kind names the wait before the reissue and the count [`classify`]
/// bounds it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reissue {
    /// `503 write_busy`, the board's write permits all held.
    ///
    /// It is reissued once, after [`WRITE_BUSY_WAIT`]; the reissue's own
    /// `write_busy` holds a burst.
    WriteBusy,
    /// `durability`, the board's durability barrier failed.
    ///
    /// It is reissued as-is, a first and a second time.
    Durability,
}

impl Reissue {
    /// Returns the wait before the reissue.
    fn wait(self) -> Duration {
        match self {
            Reissue::WriteBusy => WRITE_BUSY_WAIT,
            Reissue::Durability => Duration::ZERO,
        }
    }
}

/// The reissues one write has been given so far, and its line's clock.
///
/// The reissues are what [`classify`] bounds the next by: a `write_busy`
/// reissued once, its second holding a burst, and a `durability` twice, its
/// third holding a burst (§3c.4's riders). Counted by the caller as it
/// reissues ([`Reissues::note`]), so every reissue moves the write toward
/// its bound: a write is dialed four times at most within its call. A held
/// line's clock is kept beside them, across its probes
/// ([`Reissues::failed`]): its first failed send, from which
/// [`HAND_OVER_DEADLINE`] runs, and the last failure's token; and the sends
/// that have taken the line for their dials ([`Reissues::outs`]). Not `Copy`,
/// for the token's sake: [`classify`] reads it by reference.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Reissues {
    write_busy: u32,
    durability: u32,
    /// How many sends have taken the line for their dials ([`LineOut`]).
    ///
    /// It is counted as each send takes the line, never lowered — not by
    /// the person's `send`, which clears the clock — and read by no
    /// [`classify`]: a drop whose read was out finds it moved where a send
    /// took the line meanwhile, and acts on nothing (`Holds::still_as_read`;
    /// skep #983).
    outs: u64,
    /// The line's first failed send, from which [`HAND_OVER_DEADLINE`] runs.
    ///
    /// Set at the line's first failed send and never moved later, by the
    /// line's birth where its first dial failed ([`Holds::enter_line`]) and by
    /// each failed send after it; read by no [`classify`]. The person's
    /// `send` clears it, so the clock starts afresh at the line's next failed
    /// send.
    first_failed: Option<Moment>,
    /// The last failed send's token: its held cause, or the board's.
    ///
    /// It is what the hand-over names (`answers_lost`'s `last`) and what the
    /// resend's "sent again" is said once per change of. The person's `send`
    /// clears it.
    last: Option<String>,
}

impl Reissues {
    /// Notes one reissue of `kind` given.
    fn note(&mut self, kind: Reissue) {
        match kind {
            Reissue::WriteBusy => self.write_busy += 1,
            Reissue::Durability => self.durability += 1,
        }
    }

    /// Notes a failed send of the line at `at`, `token` its failure's.
    ///
    /// The clock starts at the line's first and is never moved later, and
    /// `token` is the last from here. It answers whether `token` differs from
    /// the last failure's token as it stood — a line's first failure among
    /// them — so the resend says "sent again" once per change.
    fn failed(&mut self, token: String, at: Moment) -> bool {
        self.first_failed.get_or_insert(at);
        let changed = self.last.as_deref() != Some(token.as_str());
        self.last = Some(token);
        changed
    }
}

/// One instant on a line's two clocks (`Reissues::first_failed`).
///
/// It is the wall's instant, from which the hand-over's time is named, and
/// the board's answering clock then (`BoardHold::answering_at`), from which
/// [`HAND_OVER_DEADLINE`] runs (§3c.4; skep #863).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Moment {
    at: Instant,
    answering: Duration,
}

/// How long a line's clocks have run since its first failed send.
///
/// It is read by [`Holds::since_first_failure`] for the deadline's two
/// readers, the resend's read and the shift.
#[derive(Debug, Clone, Copy)]
struct Elapsed {
    /// The board's answering time: what [`HAND_OVER_DEADLINE`] is held to.
    answering: Duration,
    /// The wall time: what the hand-over names.
    wall: Duration,
}

/// Returns the token of the failed send a line's `reason` says, if any.
///
/// A send fails where its dial left, or was answered, and did not land
/// ([`HAND_OVER_DEADLINE`]), so a reason says one unless no dial of the line
/// left: a connection never made (`unreachable`, `sent` false — the same
/// cause with `sent` is an answer lost), a signature not made
/// (`head_unreadable`), or a hold before any dial (`halted`, `stopped`,
/// `behind`) — or unless the dial met the death signal (`session_died`),
/// which is neither (§3c.4). Every other cause is the board's answer:
/// `poisoned`, `durability`, `moved`, a refused run's token. The token is
/// the cause. It reads a dial's own reason; a held line's reason keeps an
/// earlier dial's `sent` through a resend that never left. A reason alone
/// does not tell a second `write_busy`, held `unreachable` with `sent`
/// false, from a connection never made: the dial's refusal does, read
/// beside it ([`held_failure`]).
fn failed_send(reason: &Reason) -> Option<&str> {
    let left = match reason.cause.as_str() {
        cause::UNREACHABLE => reason.sent,
        cause::HEAD_UNREADABLE | cause::SESSION_DIED | cause::HALTED | cause::STOPPED | cause::BEHIND => false,
        _ => true,
    };
    left.then_some(reason.cause.as_str())
}

/// Returns the token of the failed send a dial's hold was, if it was one.
///
/// `reason` is the line's as the dial's answer held it and `refusal` the
/// answer, the pair a [`Dialed::Held`] carries. The reason says it
/// ([`failed_send`]) save where the board answered a hold the reason reads
/// as no dial's: a second `write_busy` is held `unreachable` with `sent`
/// false, as a connection never made is, and is a failed send all the same,
/// its token the board's. A refusal of the shell's own beside such a reason
/// — the connection never made, a signature not made — is none.
fn held_failure(reason: &Reason, refusal: &Refusal) -> Option<String> {
    failed_send(reason).map(str::to_owned).or_else(|| match refusal {
        Refusal::Board(r) => Some(r.token()),
        _ => None,
    })
}

/// Returns whether a read's halt is a request the board gave no answer to.
///
/// It is `DialError::unanswered`: §3c.5's five cases.
///
/// It is the one test the hold's reads take it by — the resend's read and
/// its site's, a shift's read, the hands' read, a `/health` — so a refusal,
/// an answer no read takes, or a request refused before any connection
/// opened, which reached no board, is never the board's silence.
fn unanswered(h: &Halt) -> bool {
    matches!(h, Halt::Dial(e) if e.unanswered())
}

/// Returns a duration in whole milliseconds, saturating at `u64::MAX`.
fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Classifies a write's outcome by the classification table (§3c.4).
///
/// The outcome, and the reissues the same write has been given, go to
/// exactly one row — the one owner of every reissue's bound.
fn classify(outcome: DialOutcome<'_>, given: &Reissues) -> Decision {
    match outcome {
        DialOutcome::Dial(e) => match e {
            // The scheme this build does not hold, or a request refused before
            // any connection opened — faced as built, no probe ends either.
            DialError::NotHeld(_) | DialError::Request(_) => Decision::Neither,
            // No connection was made — the write did not leave, and the board
            // gave it no answer.
            DialError::Connect(_) | DialError::Resolve(_) | DialError::Tls(_) => Decision::Unanswered { sent: false },
            // The request left and the board gave it no answer — a read past
            // its bound, a connection closed before any answer, and a later
            // transport error the library reads so (the enum is
            // non-exhaustive): it may have landed.
            e if e.unanswered() => Decision::Unanswered { sent: true },
            // The board answered with bytes this client cannot read — an
            // answer lost on the way: it may have landed, the resend reading
            // first.
            _ => Decision::Hold { cause: cause::UNREACHABLE, sent: true },
        },
        DialOutcome::Rejected { code, disposition } => match code {
            // `poisoned` may have landed (§3c.2): the board's write path failed
            // after the write's frames reached its journal, and a restart's
            // open "rebuilds the line from the journal" (wire.md §Rejection
            // codes) — a burst lands at the restart, so the resend reads before
            // it sends, as after a lost answer. A `halted` hold (the feed's
            // `writes.halted` read, before any dial) stays `sent: false`.
            "poisoned" => Decision::Hold { cause: cause::POISONED, sent: true },
            // `internal_panic` may have landed too (§3c.2): the board's catch
            // answers it for a write whose handler panicked — past its
            // commit, the position on the feed as a bare entry
            // (`operations.md` §4 row 34); in the kernel's commit region, the
            // write paths halted and the frames left for the restart; or
            // before any commit. The `500` is no verdict on the write, only
            // its lost answer, so a burst is held as a dial's lost answer is,
            // and the resend reads before it sends. The body rides no
            // `disposition`, so the code alone names the row.
            "internal_panic" => Decision::Hold { cause: cause::UNREACHABLE, sent: true },
            // "A silent reissue after a short wait" (§3c.4), once: the
            // reissue's own `write_busy` holds a burst (skep #786), the board
            // briefly full and the write committing nothing, so `sent: false`
            // and the resend reads for no landing; its cause `unreachable`,
            // as §3c.4 names it. A write the hold never holds faces it.
            "write_busy" => {
                if given.write_busy == 0 {
                    Decision::Reissue(Reissue::WriteBusy)
                } else {
                    Decision::Hold { cause: cause::UNREACHABLE, sent: false }
                }
            }
            // The rider (§3c.4): a third `durability` on the same write holds
            // a burst.
            "durability" => {
                if given.durability >= 2 {
                    Decision::Hold { cause: cause::DURABILITY, sent: false }
                } else {
                    Decision::Reissue(Reissue::Durability)
                }
            }
            // A burst typed against an older state of its document's
            // arrangement (wire.md §Arrangement, the typed state): `permanent`,
            // the same frame never lands, so it is held as a moved document,
            // never a refused run whose resend meets the same refusal — the
            // person places the text against the document as it stands
            // (§3c.5).
            "arrangement_moved" => Decision::Moved,
            _ => match disposition {
                "permanent" | "reorder" => Decision::Refused,
                _ => Decision::Neither,
            },
        },
    }
}

/// What an `/op` under a session answers the page (§4b.1's `op` row; §3c.4).
#[derive(Debug)]
pub enum OpAnswer {
    /// The board's ack, the shell's `held` for a burst, or a refusal.
    ///
    /// The refusal is faced at the act.
    Answered(Result<Value, Refusal>),
    /// The death signal on the session's token, and what the hold made of
    /// the frame that met it.
    ///
    /// The caller ends the session (§3c.4: the death signal is neither held
    /// nor faced), then answers by the frame's arm.
    Died(AtDeath),
}

#[cfg(test)]
impl OpAnswer {
    /// Returns the answer of a send that met no death signal.
    ///
    /// It is the suites' seam where a burst is held and no death armed.
    ///
    /// # Panics
    ///
    /// Panics where the send met the death signal.
    pub(crate) fn answered(self) -> Result<Value, Refusal> {
        match self {
            OpAnswer::Answered(answer) => answer,
            OpAnswer::Died(at_death) => panic!("the send met the death signal: {at_death:?}"),
        }
    }
}

/// What the hold made of a frame whose send met the death signal (§3c.4).
///
/// The caller ends the session first, so the death's reason is derived,
/// and answers by the arm after it.
#[derive(Debug)]
pub enum AtDeath {
    /// A frame that is no burst — a read, or a write the hold never holds:
    /// nothing is held, and the call answers `session_died`.
    NotABurst,
    /// A burst held `session_died`, `sent: false` unless a shifted dial of
    /// it left: the call answers `held` once the line takes the death's
    /// reason ([`Holds::note_death`]).
    Held(DeathHeld),
    /// A burst the hold could not hold: the refusal the call answers,
    /// `held_full` or `store_halted`.
    Refused(Refusal),
}

/// A burst held at the death signal, its answer waiting for the death's
/// reason.
///
/// It is the line's ordinal and the `held` answer the call gives, both the
/// hold's alone: [`Holds::note_death`] gives the line the reason the
/// session's end derived and hands back the answer, so no caller answers
/// the page with a line that does not carry it.
#[must_use = "the line takes the death's reason, and the call its answer, by `Holds::note_death`"]
#[derive(Debug)]
pub struct DeathHeld {
    k: u64,
    answer: Value,
}

/// The person's two acts on a held line.
///
/// They are §4b.1's `resolve` row's, as the row's `act` spells them — read
/// off the call's arguments by [`ResolveAct::named`] alone, so no act
/// reaches the hold that the row does not spell. The send takes a refused
/// run's line or a moved document's (P10); the drop takes any line, under
/// any session, and where a dial of a line it takes may have left this
/// device, reads for that line's landing first or names the line in its
/// answer ([`Holds::resolve`]). Neither takes a line a send has out for its
/// dials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveAct {
    /// `"drop"`: the line dropped, with the lines after it on its document.
    ///
    /// The lines after it are every later line of its document: a refused
    /// run's `behind` lines, a moved document's later lines, the lines held
    /// behind a holding one. Under a session that may write, a line marked
    /// `sent` that is holding or was handed over as `answers_lost`, some dial
    /// of it possibly having left the device, is read for its landing first,
    /// and kept where it landed, its later lines standing (skep #866, #983).
    /// Every other line it takes that may have landed is named in its answer
    /// ([`Resolved::Dropped`]; skep #993).
    Drop,
    /// `"send"`: the document's waiting lines handed back.
    ///
    /// They go back to the automatic machine.
    Send,
}

impl ResolveAct {
    /// Returns the act the row spells `act`: `"drop"` or `"send"`.
    ///
    /// It answers none for any other spelling.
    pub fn named(act: &str) -> Option<ResolveAct> {
        match act {
            "drop" => Some(ResolveAct::Drop),
            "send" => Some(ResolveAct::Send),
            _ => None,
        }
    }
}

/// What a `resolve` act did (§4b.1's `resolve` row).
///
/// The call answers `{}` where the lines were handed back or dropped,
/// `{may_have_landed: [k, …]}` where a drop took lines that may have landed,
/// `{kept: true}` where a drop found its line landed, and the session's death
/// where the drop's read met it (the shell's `resolve` row).
#[must_use = "a `HandedBack` or `Kept` document's lines wait on the probe its caller hands the board's feed thread, a `Died` session on the end its caller runs, and a `Dropped` act's lines that may have landed on the answer that names them"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// `"drop"`: the line `done … dropped`, with the lines after it.
    ///
    /// The lines after it on its document — a refused run's `behind` lines,
    /// a moved document's later lines, the lines held behind a holding one —
    /// are dropped with it.
    Dropped {
        /// The lines dropped whose words may stand on the board, in `k` order.
        ///
        /// Each may have landed ([`PrincipalHold::may_have_landed`]), and no
        /// read of the drop's own ruled its landing out: a refused run's or
        /// a moved document's line marked `sent`, the keyless session's
        /// discard of one, a `sent` line behind the one the drop read
        /// (§3c.4; skep #993). They are dropped all the same, and a landing
        /// that stands shows in the feed's next `drafts` row and the next
        /// `image` read.
        may_have_landed: Vec<u64>,
    },
    /// `"send"`: the document's waiting lines re-marked `behind`.
    ///
    /// They are handed back to the automatic machine (§3c.4; §4b.1: "handed
    /// to the machine"), each keeping its `sent` and its clock started
    /// afresh — the caller hands the board's feed thread its probe, so the
    /// call answers once the lines are handed back, never after a resend's
    /// ack.
    HandedBack,
    /// `"drop"` whose read for the line's landing found it landed.
    ///
    /// The line, one that may have landed ([`Holds::resolve`]), is `done
    /// kept` and nothing is dropped (§3c.4; skep #866, #983): the lines
    /// behind it on its document were typed after a write the board kept,
    /// and go out in order at the probe the caller hands the board's feed
    /// thread.
    Kept,
    /// `"drop"` whose read for the line's landing met the death signal.
    ///
    /// Nothing is dropped, the line standing for the session that stands
    /// next, and the caller ends the session: the death is neither a landing
    /// nor its absence (§3c.4).
    Died,
}

/// Why a drop that reads first cannot tell whether its line landed.
///
/// It is the `why` of the `landing_unread` refusal (§3c.4; skep #866), in
/// the words `shapes`' `LandingUnreadRefusal` declares: the drop of a line
/// that may have landed reads for the line's landing first
/// ([`Holds::resolve`]; skep #983), and drops nothing where the read cannot
/// tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LandingUnread {
    /// The board gave the read no answer, or is not answering the hold.
    ///
    /// Its last `/health` found it silent, or a request of the hold's there
    /// pends its verdict, and the read is not made (§3c.5).
    Unanswered,
    /// The board answered the read, or its site read, with no page.
    Unread,
    /// A row could be the line's landing, and the read could not confirm it.
    Undecided,
    /// The own node stands stopped by its owner's act: no read is made.
    Stopped,
    /// The board's write path stands poisoned: no read is made.
    ///
    /// A restart rebuilds the board's write path from its journal, so a
    /// landing no read sees yet may stand after it.
    Poisoned,
    /// The board's writes stand halted: no read is made, as at `Poisoned`.
    Halted,
}

impl LandingUnread {
    /// Every why, in the order the declaration spells them.
    #[cfg(test)]
    const ALL: [LandingUnread; 6] = [LandingUnread::Unanswered, LandingUnread::Unread, LandingUnread::Undecided, LandingUnread::Stopped, LandingUnread::Poisoned, LandingUnread::Halted];

    /// Returns the why as the refusal spells it.
    fn as_str(self) -> &'static str {
        match self {
            LandingUnread::Unanswered => "unanswered",
            LandingUnread::Unread => "unread",
            LandingUnread::Undecided => "undecided",
            LandingUnread::Stopped => cause::STOPPED,
            LandingUnread::Poisoned => cause::POISONED,
            LandingUnread::Halted => cause::HALTED,
        }
    }
}

/// A burst admitted: a frame some send of which the board can take.
///
/// It is a frame of [`BURST_KINDS`] and its document — what every held line
/// is made of — and the page's anchors where it carried them
/// ([`Burst::with_anchors`]), which ride the line and never the frame. Built
/// by [`Burst::admit`] alone, so the hold holds no frame the burst's door
/// did not see.
#[derive(Debug)]
pub struct Burst {
    frame: Value,
    doc: String,
    anchors: Option<Anchors>,
}

impl Burst {
    /// Admits a burst by the burst's door, the one a burst enters the hold by.
    ///
    /// The refusal is faced at the act where the board would refuse the
    /// frame at every send — each such frame, held, would be sent and
    /// resolved never, and hold every later burst of its principal `behind`
    /// it for the shell's life and past it on disk.
    ///
    /// # Errors
    ///
    /// The checks run in this order, the first unmet answering:
    ///
    /// * its op one of the five kinds, else `malformed_args`;
    /// * its `doc` a document address in its one spelling
    ///   (`wire::document_address`) — what the resend's read names `under`
    ///   and a held line is keyed by — else `malformed_args`;
    /// * its `id`, where it is a string, not of the prefix the hold's resends
    ///   dial under (`refs::DialId`, `shell:`), so no burst of a page's shares
    ///   an `id` with a resend (skep #971), else `malformed_args` naming
    ///   `frame.id`;
    /// * its bytes as sent, and as every resend sends them — the attest
    ///   stripped, a dial id in the page's `id`'s place ([`DIAL_ID_ROOM`])
    ///   and, under a session whose key attests the kind
    ///   (`SessionEntry::attesting_key`), the most an attest adds
    ///   ([`attest_room`]) — within the board's frame cap
    ///   ([`MAX_FRAME_BYTES`], which the board answers `413` past, unread),
    ///   else `frame_too_large`;
    /// * an insert such a session attests composable from the frame alone
    ///   ([`insert_terms`]: its trunk, its deposit, its values within the
    ///   board's count), else `attest_not_composed`, the composer's halt.
    pub fn admit(frame: Value, session: &SessionEntry) -> Result<Burst, Refusal> {
        if !is_burst(&frame) {
            return Err(Refusal::malformed("frame.op"));
        }
        let doc = frame["doc"].as_str().filter(|d| document_address(d).is_some()).ok_or_else(|| Refusal::malformed("frame.doc"))?.to_string();
        if frame["id"].as_str().is_some_and(DialId::reserves) {
            return Err(Refusal::malformed("frame.id"));
        }
        let attested = frame["op"].as_str().and_then(|op| session.attesting_key(op)).is_some();
        let sent_bytes = json_len(&frame);
        // A resend dials the frame the line stores under the line's dial id:
        // the attest a page supplied, which is never stored, and the page's
        // `id` each give way — `,"<name>":` and the value — to the dial id's
        // member and, where the session's key attests the kind, the shell's.
        let member = |name: &str| frame.get(name).map_or(0, |v| ",\"\":".len() + name.len() + json_len(v));
        let resent_bytes = sent_bytes.saturating_sub(member("attest") + member("id")) + DIAL_ID_ROOM + if attested { attest_room() } else { 0 };
        if sent_bytes.max(resent_bytes) > MAX_FRAME_BYTES {
            return Err(Refusal::shell(Name::FRAME_TOO_LARGE, json!({"bytes": sent_bytes.max(resent_bytes), "cap": MAX_FRAME_BYTES})));
        }
        if attested && frame["op"] == "insert" {
            insert_terms(&frame).map_err(|h| Refusal::of_named(Name::ATTEST_NOT_COMPOSED, h))?;
        }
        Ok(Burst { frame, doc, anchors: None })
    }

    /// Returns the burst carrying `anchors`: the page's, read at the `op`
    /// row's door (`held::Anchors::of`), or none.
    ///
    /// A burst without them is admitted all the same, as an unshiftable one:
    /// an agent through the MCP tools sends none, and its stale burst is held
    /// as a moved document.
    pub fn with_anchors(self, anchors: Option<Anchors>) -> Burst {
        Burst { anchors, ..self }
    }

    /// Returns the frame as the page composed it.
    fn frame(&self) -> &Value {
        &self.frame
    }

    /// Returns the burst as a held line stores it (§3c.2).
    ///
    /// It is its document in its one spelling, its frame with any `attest`
    /// stripped — the resend composes its own when it sends — and its
    /// anchors, the line's and never the wire's.
    fn into_stored(self) -> (String, Value, Option<Anchors>) {
        let Burst { mut frame, doc, anchors } = self;
        if let Some(members) = frame.as_object_mut() {
            members.remove("attest");
        }
        (doc, frame, anchors)
    }
}

/// What one dial of a write answered, read once through the table.
#[derive(Debug)]
enum Dialed {
    /// The board's ack.
    Acked(Value),
    /// A hold-class answer, a refused run, or a moved document's verdict.
    ///
    /// It carries the line's reason for a burst, and the refusal the answer
    /// is, which a write the hold never holds faces.
    Held { reason: Reason, refusal: Refusal },
    /// A request the board gave no answer to (skep #863).
    ///
    /// The dial itself, a read the attest's composer made, or the read a
    /// shift makes before its dial ([`Decision::Unanswered`]). It carries the
    /// line's reason — `unreachable`, its `sent` the dial's — and the
    /// refusal, which a write the hold never holds faces. No failed send is
    /// noted for it at once ([`Dialed::failure`]): the next probe's verdict
    /// settles whether the dial was the line's own failure (`Answering`).
    Unanswered { reason: Reason, refusal: Refusal },
    /// A reissue-class answer, with its kind.
    ///
    /// It carries the refusal it is, faced where no reissue follows.
    Reissue { kind: Reissue, refusal: Refusal },
    /// An answer faced at the act.
    ///
    /// It is the board's refusal the table holds and reissues nowhere, or
    /// the shell's own: a request refused before any connection, or an
    /// attest that could not be composed — the composer's own halt, or a
    /// read it made refused.
    Faced(Refusal),
    /// The death signal on the session's token.
    ///
    /// It was met at the dial or at a read the attest's composer made.
    Died,
}

impl Dialed {
    /// Returns a refusal read through the table.
    ///
    /// It is held for its cause, held as a refused run with the board's
    /// `token` and verdict, held as a moved document with the verdict,
    /// reissued, or faced — each beside the refusal the answer is.
    fn refused(decision: Decision, token: &str, verdict: Value, refusal: Refusal) -> Dialed {
        match decision {
            Decision::Hold { cause, sent } => Dialed::Held { reason: Reason::of(cause, sent), refusal },
            Decision::Unanswered { sent } => Dialed::unanswered(sent, refusal),
            Decision::Refused => Dialed::Held { reason: Reason::refused(token, verdict), refusal },
            // The verdict rides the moved line — the state the burst was typed
            // against and the document's current one — so the line keeps both
            // across a relaunch, and the shift reads its floor off it; a
            // refused burst landed nothing.
            Decision::Moved => Dialed::Held { reason: Reason { cause: cause::MOVED.to_string(), refusal: Some(verdict), sent: false }, refusal },
            Decision::Reissue(kind) => Dialed::Reissue { kind, refusal },
            Decision::Neither => Dialed::Faced(refusal),
        }
    }

    /// Returns a request the board gave no answer to, held `unreachable`.
    ///
    /// `sent` is whether a byte of the request may have left
    /// ([`Decision::Unanswered`]), and `refusal` what the write faces.
    fn unanswered(sent: bool, refusal: Refusal) -> Dialed {
        Dialed::Unanswered { reason: Reason::of(cause::UNREACHABLE, sent), refusal }
    }

    /// Returns the token of the failed send this dial was, if it was one.
    ///
    /// A send fails where its dial left, or was answered, and did not land
    /// ([`HAND_OVER_DEADLINE`]): every answer but an ack and the death
    /// signal, save a dial that never left — a hold no dial left by
    /// ([`failed_send`]: a connection never made, a signature not made) and
    /// a refusal of the shell's own, a request refused before any connection
    /// or an attest's composer halted — and a hold the board answered is one
    /// whatever its reason reads as ([`held_failure`]). A request the board
    /// gave no answer to is none here: the next probe's verdict settles it
    /// (`Answering::Unanswered`).
    /// The token is the held cause, or the board's in the `code:detail`
    /// convention, the token a refused run's line carries.
    ///
    /// **Precondition.** The dial was made, its attest composed: an attest
    /// that could not be composed answers a board's refusal of a read its
    /// composer made as that refusal, which says nothing of the line's send.
    fn failure(&self) -> Option<String> {
        match self {
            Dialed::Held { reason, refusal } => held_failure(reason, refusal),
            Dialed::Reissue { refusal: Refusal::Board(r), .. } | Dialed::Faced(Refusal::Board(r)) => Some(r.token()),
            Dialed::Acked(_) | Dialed::Unanswered { .. } | Dialed::Reissue { .. } | Dialed::Faced(_) | Dialed::Died => None,
        }
    }

    /// Returns whether this answer leaves the dial's write possibly landed.
    ///
    /// It does at an ack, the write landed, and at the rows of [`classify`]'s
    /// table whose `sent` stands: an answer lost once the request left, the
    /// board's `internal_panic`, a `poisoned` answer. Every other answer
    /// committed nothing — a connection never made, a refusal, a
    /// reissue-class answer, the board's verdict on the typed state, the
    /// death signal — so a line its every dial met so stands in
    /// [`PrincipalHold::never_left`] (skep #983).
    fn may_have_landed(&self) -> bool {
        match self {
            Dialed::Acked(_) => true,
            Dialed::Held { reason, .. } | Dialed::Unanswered { reason, .. } => reason.sent,
            Dialed::Reissue { .. } | Dialed::Faced(_) | Dialed::Died => false,
        }
    }
}

/// What a send answers where its attest could not be composed.
///
/// Nothing is dialed ([`Holds::attest_where_owed`]): the death signal met
/// at one of the composer's reads; a read the board gave no answer to a
/// request unanswered (skep #863), and one whose answer could not be read
/// held like the dial's own failure, each `sent: false`, since the write
/// never left; a signature the board's head record could not be read for
/// held `head_unreadable`, `sent: false`, its line carrying the refusal that
/// says why — a burst so held, any other write so refused (SP-14); the
/// composer's own refusal faced.
impl From<Unattested> for Dialed {
    fn from(why: Unattested) -> Dialed {
        match why {
            Unattested::Died => Dialed::Died,
            // The table's transport rows read no reissue count.
            Unattested::Refused(Refusal::Unreachable(e)) => match classify(DialOutcome::Dial(&e), &Reissues::default()) {
                Decision::Unanswered { .. } => Dialed::unanswered(false, Refusal::Unreachable(e)),
                Decision::Hold { cause, .. } => Dialed::Held { reason: Reason::of(cause, false), refusal: Refusal::Unreachable(e) },
                _ => Dialed::Faced(Refusal::Unreachable(e)),
            },
            // Never sent unsigned: the line holds until the record reads,
            // carrying why it waits.
            Unattested::Refused(refusal @ Refusal::Halt { name: Name::HEAD_UNREADABLE, .. }) => {
                let reason = Reason { cause: cause::HEAD_UNREADABLE.to_string(), refusal: Some(refusal.to_value()), sent: false };
                Dialed::Held { reason, refusal }
            }
            Unattested::Refused(refusal) => Dialed::Faced(refusal),
        }
    }
}

/// A frame as a send under a session dials it, attested where one is owed.
///
/// It is a copy carrying the attest the session's key signs where that key
/// attests the frame's kind and no attest rides it yet
/// (`SessionEntry::attest`, `wants_attest`), and the frame borrowed as it
/// stands otherwise — a bare session's frame, a read, a kind outside the
/// checked set, an attest the page supplied, a board no one has claimed
/// that serves no head record. Made by [`Holds::attest_where_owed`] alone,
/// so [`Holds::dial`] sends no frame the session's attest did not see — and
/// never the frame a held line keeps, which carries no attest (§3c.2). A
/// resend's copy goes out under the line's dial id
/// ([`AttestedWhereOwed::under`]): no attest signs the `id`.
#[derive(Debug)]
struct AttestedWhereOwed<'f>(Cow<'f, Value>);

impl AttestedWhereOwed<'_> {
    /// Returns the frame as a resend dials it, under the line's `dial_id`.
    ///
    /// It is a copy whose envelope `id` is the dial id, in the page's `id`'s
    /// place where the page sent one (skep #971), so the board's retry memo
    /// answers it with no acknowledgment but the line's own. The attest it
    /// carries stands: the entry frame an attest signs holds no `id`.
    fn under(self, dial_id: &DialId) -> AttestedWhereOwed<'static> {
        let mut frame = self.0.into_owned();
        if let Some(members) = frame.as_object_mut() {
            members.insert("id".to_string(), Value::from(dial_id.as_str()));
        }
        AttestedWhereOwed(Cow::Owned(frame))
    }
}

/// One line entered in a principal's queue ([`Holds::enter_line`]).
///
/// It is the ordinal the line took, the `held` answer for it, and the line's
/// own face, which the `held` event says of its document as the line is
/// entered save where a line ahead of it awaits the person's act
/// ([`Holds::say_entered`]): the document, the line's state and its cause.
#[derive(Debug)]
struct LineEntered {
    k: u64,
    answer: Value,
    doc: String,
    state: HeldState,
    cause: String,
}

/// What a `held` event says of the lines standing on a document (§4b.2).
///
/// It is how many stand, and why one of them has no copy on disk, read
/// together under the board's lock ([`PrincipalHold::lines_on`]).
#[derive(Debug, Clone, Default)]
struct LinesOn {
    held: u64,
    unwritable: Option<Unwritable>,
}

/// A held line's state, and a document's as the `held` event carries it.
///
/// Its words are §4b.1's (`not_resolvable`) and §4b.2's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeldState {
    Holding,
    Sending,
    Kept,
    Refused,
    Moved,
}

impl HeldState {
    fn as_str(self) -> &'static str {
        match self {
            HeldState::Holding => "holding",
            HeldState::Sending => "sending",
            HeldState::Kept => "kept",
            HeldState::Refused => "refused",
            HeldState::Moved => "moved",
        }
    }
}

/// Returns a held line's state.
///
/// It is in the words §4b.1's `resolve` row and §4b.2's `held` event share:
/// `moved` (a moved document's, whatever refusal stands beside it — a line
/// the board refused as typed against an older state keeps the verdict),
/// `refused` (a refused run's), else `holding` — a line held
/// `head_unreadable` among them, whose refusal says why it waits, and a line
/// held `session_died`, whose refusal is the death's and which awaits a
/// session that may write, each awaiting no act of the person's (P10) save
/// the drop, the person's discard ([`Holds::resolve`]; skep #726, #983);
/// `sending` is the resend's, never a line's at rest.
fn line_state(reason: &Reason) -> HeldState {
    if reason.cause == cause::HEAD_UNREADABLE || reason.cause == cause::SESSION_DIED {
        HeldState::Holding
    } else if reason.cause == cause::MOVED {
        HeldState::Moved
    } else if reason.refusal.is_some() {
        HeldState::Refused
    } else {
        HeldState::Holding
    }
}

/// Returns whether a line held for `reason` waits for the person's act.
///
/// It does for a refused run's, or a moved document's (§3c.4, §3c.5): no
/// probe sends it, and `resolve` alone moves it.
fn awaits_act(reason: &Reason) -> bool {
    matches!(line_state(reason), HeldState::Refused | HeldState::Moved)
}

/// Returns the typed state the board's verdict on a moved line echoes.
///
/// It is the `site.as_of` of the `arrangement_moved` a line held `moved`
/// carries: the position the hands that moved its document are read since
/// (§3c.5; [`Holds::hands_since_typed_state`]). It is none for a line held
/// for any other cause, and for a moved line that carries no such verdict,
/// whose hands no read names.
fn typed_state(reason: &Reason) -> Option<u64> {
    reason.refusal.as_ref().filter(|_| reason.cause == cause::MOVED)?["site"]["as_of"].as_u64()
}

/// Why a held line stands with no copy on disk, as the `held` answer says it
/// (§3c.3; skep #820).
///
/// It is the words the answer carries as `unwritable` and their class, which
/// it carries beside them as `unwritable_class`, both made from one cause so
/// neither is said without the other: an I/O refusal's words with its kind's
/// class ([`UnwritableClass::of`]) — the device's refusal of the line's
/// copy, or of the store: the held directory or its lock, the file's read,
/// the renumbering copy the read owed ([`store_refused`]).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Unwritable {
    why: String,
    class: UnwritableClass,
}

impl Unwritable {
    /// Sets the `held` answer's two members: `unwritable`, the words, and
    /// `unwritable_class`, their class.
    fn answer_in(&self, answer: &mut Value) {
        answer["unwritable"] = Value::from(self.why.as_str());
        answer["unwritable_class"] = Value::from(self.class.as_str());
    }
}

/// Returns the store's refusal `e` said after `lead`, as `<lead>: <e>`, of
/// `e`'s kind.
///
/// It is the one spelling of a device's refusal of the store — the held
/// directory or its lock, the file's read, the renumbering copy — kept in
/// its kind so the `held` answer's class reads off it ([`Unwritable`]).
fn store_refused(lead: &str, e: &io::Error) -> io::Error {
    io::Error::new(e.kind(), format!("{lead}: {e}"))
}

impl From<&io::Error> for Unwritable {
    /// Returns the I/O refusal `e` in its own words, of its kind's class.
    fn from(e: &io::Error) -> Unwritable {
        Unwritable { why: e.to_string(), class: UnwritableClass::of(e.kind()) }
    }
}

/// The class of a cause that keeps a held line off disk: the act the page
/// offers turns on it (§3c.3, the face's act keyed by cause; skep #820).
///
/// It is read off an I/O refusal's kind alone, never its words, which differ
/// by platform: `full` where freeing space lets the copy land, `read_only`
/// where the volume, or this shell's rights on the data directory, refuse
/// the write, which no space freed ends, and `other` for every other kind,
/// and for every cause no device gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnwritableClass {
    /// A device with no room left, or a quota spent.
    Full,
    /// A read-only volume, or a write this shell has no right to make.
    ReadOnly,
    /// Any other cause.
    Other,
}

impl UnwritableClass {
    /// Returns the class of an I/O refusal of `kind`: the one table.
    fn of(kind: io::ErrorKind) -> UnwritableClass {
        match kind {
            io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded => UnwritableClass::Full,
            io::ErrorKind::ReadOnlyFilesystem | io::ErrorKind::PermissionDenied => UnwritableClass::ReadOnly,
            _ => UnwritableClass::Other,
        }
    }

    /// Returns the class as the `held` answer's `unwritable_class` spells it.
    fn as_str(self) -> &'static str {
        match self {
            UnwritableClass::Full => "full",
            UnwritableClass::ReadOnly => "read_only",
            UnwritableClass::Other => "other",
        }
    }
}

/// A held directory under this shell's lock (§3c.3).
///
/// It is the directory and the `flock` on its `lock`, held while the value
/// stands: the pending one and the board's own, each for the shell's life
/// once taken ([`Directory::ThisWindow`]).
#[derive(Debug)]
struct LockedDir {
    dir: HeldDir,
    _lock: File,
}

/// The board's held store (§3c.1) as this shell stands to it: its three
/// states, the pending store's and the board's own.
#[derive(Debug)]
enum Directory {
    /// Not this shell's yet, for a device's refusal alone: the pending
    /// directory, or its lock, could not be made.
    ///
    /// The refusal is the device's — a read-only volume, a directory this
    /// shell may not write — spelled with what was refused
    /// ([`store_refused`]), and is what every line held meanwhile answers as
    /// `unwritable`, of the refusal's kind's class: no lock of the board's is
    /// held, no file is read, and each principal's lines wait in memory in
    /// their queue, which names its file all the same
    /// (`HeldQueue::unopened`). Tried again at every copy, every probe and
    /// every touch of the store ([`Holds::retry_store`],
    /// [`Holds::touch_store`]): the one retry makes the directory, takes its
    /// lock, reads each file and writes the lines, in that order. It is the
    /// store's standing before the first touch too, under no refusal yet.
    NotYet(io::Error),
    /// Another shell's: a lock of the board's held store — the pending
    /// directory's, or the board's own — was found held by another shell
    /// over this data directory (§3c.3).
    ///
    /// ONE SHELL PER DATA DIRECTORY: a second launch hands its address to the
    /// running client and exits. Until that hand-off stands, a shell finding
    /// either lock held takes none — it lets go any it took in that try —
    /// and reads alone at the board, one writer per board (skep #828, #873):
    /// every write refused `another_window` at the door before any dial
    /// ([`Holds::another_window`]) and at the hold's own door behind it
    /// ([`Holds::enter_line`]), nothing held and nothing sent, and no
    /// principal's file opened. The lines held before the state was found
    /// stand, and are sent as the board takes them: those on the pending
    /// file where this shell took the pending lock at an earlier try and
    /// then found the board's own held — `pending`, kept for the shell's
    /// life as every lock taken is, so each line's marks and its `done` are
    /// written there and no other shell opens the file — and those in
    /// memory, held while the device refused the store (skep #789). Both
    /// locks are tried again at every probe and at every touch of the store
    /// ([`Holds::touch_store`]: a session's open, a ceremony's door), and the
    /// state is left once both are this shell's. Its start and its end
    /// are each said on `Talk` and emitted as `another-window` once
    /// ([`Holds::step`]).
    AnotherWindow { pending: Option<LockedDir> },
    /// This shell's for its life: the pending store, and the board's own
    /// once a term has read and its directory is made and locked.
    ///
    /// `pending` is `held/pending/<hash of the origin dialed>/`, made `0700`
    /// and locked at the board's first touch whatever its head read answered
    /// — the one directory named by an origin (§3c.1; skep #725), so a line
    /// goes to disk before any head reads; it stands, empty but for its lock
    /// file, for every board the shell touches, and its lock is never let
    /// go. `chain` is `held/<chain>/`, made and locked after it where a term
    /// has read — at the first touch, or at a later probe or touch, the
    /// pending lock taken first (skep #828) — and never let go either: the
    /// queues' files move from the pending one to it once
    /// ([`Holds::settle_queue`]), the pending FILE removed once no copy is
    /// owed, the directory and its lock standing. `None` while no term has
    /// read, or while the device refuses the board's own directory or its
    /// lock — said once, tried again at every probe and every touch, the
    /// lines on the pending file meanwhile.
    ThisWindow { pending: LockedDir, chain: Option<LockedDir> },
}

/// What one try of the board's locks found ([`Directory::step`]).
struct Stepped {
    /// The store as the try left it.
    next: Directory,
    /// The device's refusal of the board's own directory or its lock, where
    /// the try met one with the pending store this shell's: said once, the
    /// lines on the pending file meanwhile.
    chain_refused: Option<io::Error>,
}

impl Directory {
    /// Returns whether a try of the board's locks is owed here: the store is
    /// not yet whole — the board's own lock not held, a term read or not.
    fn tries(&self) -> bool {
        !matches!(self, Directory::ThisWindow { chain: Some(_), .. })
    }

    /// Tries the board's locks this shell does not hold, once, and returns
    /// the store as the try leaves it (§3c.1, §3c.3; skep #828, #873).
    ///
    /// `chain` is the board's chain as its head last named it, where one has
    /// (`BoardHold::chain`). The pending lock first: taken where it is not
    /// this shell's already — a lock this shell holds is never tried again,
    /// since `flock` is the open file's and a second open's try would answer
    /// it held — the directory made `0700`; found held, the store is another
    /// shell's, nothing taken. Then the board's own, where a term has read:
    /// found held, the store is another shell's — the pending lock let go
    /// where this try took it, kept where an earlier one did — so two
    /// shells never stand each holding one of the board's locks, both
    /// writing, and the shell that holds the pending lock takes the board's
    /// own at its next try, the board's one writer; its directory or lock
    /// refused by the device, the pending store stands this shell's and the
    /// refusal is answered for the shell to say once. The pending directory
    /// or its lock refused by the device is the store not yet this shell's,
    /// the refusal kept for every line held meanwhile.
    fn step(self, data_dir: &Path, origin: &Origin, chain: Option<Chain>) -> Stepped {
        let stepped = |next: Directory| Stepped { next, chain_refused: None };
        // The pending lock: this shell's already, or tried now.
        let (pending, held_before) = match self {
            Directory::ThisWindow { chain: Some(_), .. } => return stepped(self),
            Directory::ThisWindow { pending, chain: None } | Directory::AnotherWindow { pending: Some(pending) } => (pending, true),
            Directory::AnotherWindow { pending: None } | Directory::NotYet(_) => {
                let dir = HeldDir::pending(data_dir, origin);
                match dir.ensure().and_then(|()| dir.try_lock()) {
                    Ok(Some(lock)) => (LockedDir { dir, _lock: lock }, false),
                    Ok(None) => return stepped(Directory::AnotherWindow { pending: None }),
                    Err(e) => return stepped(Directory::NotYet(store_refused("the board's held store could not be made or locked", &e))),
                }
            }
        };
        // The board's own, where a term has named it.
        let Some(chain) = chain else { return stepped(Directory::ThisWindow { pending, chain: None }) };
        let dir = HeldDir::new(data_dir, chain);
        match dir.ensure().and_then(|()| dir.try_lock()) {
            Ok(Some(lock)) => stepped(Directory::ThisWindow { pending, chain: Some(LockedDir { dir, _lock: lock }) }),
            // A pending lock this try took is let go with `pending`.
            Ok(None) => stepped(Directory::AnotherWindow { pending: held_before.then_some(pending) }),
            Err(e) => Stepped { next: Directory::ThisWindow { pending, chain: None }, chain_refused: Some(store_refused("the board's own held store could not be made or locked", &e)) },
        }
    }
}

/// The key the `held` event's memory keeps a document's last state under:
/// the board's reference, the session's and the document ([`Holds::last_emitted`]).
type HeldKey = (String, String, String);

/// What the `held` event last said of a document (`Holds::last_emitted`).
///
/// It is the members the event repeats where a retry lands
/// ([`Holds::say_landed`]) and those a repeat is judged by
/// ([`HeldSaid::repeated_by`]), a `moved` face's verdict among them, the one
/// its hands were read for ([`Judged`]; skep #973), and whether those hands
/// are named `again` (skep #989), or what the held list named of the
/// document, which tells no event ([`Holds::lines`]). The line a keep names
/// is none of them: it is said on the one event that keeps it
/// ([`LandedLine`]), and no repeat says it again.
#[derive(Debug, Clone)]
struct HeldSaid {
    state: HeldState,
    held: u64,
    cause: Option<String>,
    hands: Vec<Hand>,
    again: bool,
    sendable: Option<bool>,
    unwritable: Option<Unwritable>,
    judged: Option<Judged>,
}

impl HeldSaid {
    /// Returns what an event says of a document.
    ///
    /// It is the `lines` standing on it, its `state`, its `cause` and its
    /// `face`.
    fn of(lines: LinesOn, state: HeldState, cause: Option<&str>, face: MovedFace<'_>) -> HeldSaid {
        let LinesOn { held, unwritable } = lines;
        let MovedFace { hands, again, sendable, judged } = face;
        HeldSaid { state, held, cause: cause.map(str::to_owned), hands: hands.to_vec(), again, sendable, unwritable, judged: judged.cloned() }
    }

    /// Returns whether `now` would say nothing this has not said.
    ///
    /// It compares the state, the count, whether the hands are named not
    /// read, whether they are named `again` (skep #989), the `sendable`, why
    /// a line stands off disk and the verdict a moved face's hands were read
    /// for, so a face for another verdict is said (skep #973). The cause and
    /// the hands named are not asked: a document's state is said as it
    /// changes (skep #727).
    fn repeated_by(&self, now: &HeldSaid) -> bool {
        self.state == now.state
            && self.held == now.held
            && self.hands.contains(&Hand::UNREAD) == now.hands.contains(&Hand::UNREAD)
            && self.again == now.again
            && self.sendable == now.sendable
            && self.unwritable == now.unwritable
            && self.judged == now.judged
    }

    /// Returns whether this is a `moved` face told for `judged`.
    ///
    /// Its hands are then the ones read for that verdict; a face told for
    /// another names no hand of the document as it stands (skep #973).
    fn moved_for(&self, judged: Option<&Judged>) -> bool {
        self.state == HeldState::Moved && self.judged.as_ref() == judged
    }
}

/// A board's state, as the `daemon` event and `probe()` say it (§4b.2; P37).
///
/// It is the most severe that holds, in the order of its variants
/// ([`BoardHold::state`]; skep #865).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoardState {
    /// The own node stands stopped by its owner's act.
    Stopped,
    /// The board's last `/health` verdict was silence.
    Unreachable,
    /// The board's last `/health` read said its writes are halted.
    Halted,
    /// The board's head record will not read, the cause beside it.
    ///
    /// A signed write owes a signature naming the record, so none can be
    /// made while this holds (§3c.3; SP-14). A pair once read is the client's
    /// for the run (`Board::board_term`), so it holds only for a head no read
    /// of this run has had whole.
    HeadUnreadable(String),
    /// None of the others holds.
    Running,
}

impl BoardState {
    /// Returns the state as the `daemon` event and `probe()` spell it.
    pub fn as_str(&self) -> &'static str {
        match self {
            BoardState::Stopped => "stopped",
            BoardState::Unreachable => "unreachable",
            BoardState::Halted => "halted",
            BoardState::HeadUnreadable(_) => "head_unreadable",
            BoardState::Running => "running",
        }
    }

    /// Returns why the state holds, where it names why: `head_unreadable`'s
    /// cause.
    pub fn reason(&self) -> Option<&str> {
        match self {
            BoardState::HeadUnreadable(cause) => Some(cause),
            BoardState::Stopped | BoardState::Unreachable | BoardState::Halted | BoardState::Running => None,
        }
    }
}

/// One change of a board's state since it was last told.
///
/// It is [`Holds::state_change`]'s answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardEdge {
    /// The state last told.
    pub from: BoardState,
    /// The state that holds now.
    pub to: BoardState,
}

/// The board's head as the hold last read it, for the one `Talk` line at
/// each change of its state (skep #727; SP-11) and the board's state
/// ([`BoardHold::state`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum HeadState {
    /// No read of the head has decided yet.
    Unknown,
    /// The head reads — or the board is unclaimed and owes none.
    Reads,
    /// The head record stands and cannot be read, or a claimed board serves
    /// none: `head_unreadable`, with its cause.
    Unreadable(String),
}

/// Where a principal's held lines are kept at a board (§3c.3): the three
/// states.
#[derive(Debug)]
enum Custody {
    /// The file not yet read.
    ///
    /// The principal's door reads it at the first touch under a session of
    /// the principal's, where the store is this shell's; where the device
    /// refuses the store — the directory, its lock, the file's read, the
    /// renumbering copy the read owed — or another shell holds it, the file
    /// stays unread and the queue holds its lines in memory, every one owed
    /// to the file it names (`HeldQueue::unopened`), until the retry reads
    /// it ([`Holds::retry_store`]).
    Unopened,
    /// In `principal-<n>.held` — the board's own file, or the pending one —
    /// each line synced before its answer.
    ///
    /// Where the device refused a copy — a line's first, or a re-mark or a
    /// `done` of a line on disk — it and every copy owed after it wait in
    /// memory instead, written in `k` order by the retry (`HeldQueue::retry`,
    /// §3c.3), each answer for a line waiting for its first copy carrying the
    /// refusal as `unwritable` and its kind's class beside it ([`Unwritable`]).
    /// Pending or the board's own is the FILE's property
    /// (`HeldQueue::is_pending`): the queue moves from the pending file to
    /// the board's at the pending → chain change ([`Holds::settle_queue`]).
    File,
    /// Nowhere: P38's halt (§3c.3).
    ///
    /// No burst is sent and no line held for the principal at this board,
    /// each act answered `store_halted` by the principal's door,
    /// [`Holds::principal_hold`], which every act takes, its detail the
    /// `why` alone, and the resend walks none of its lines. Found at the
    /// first touch — the pending file, or the board's — before any hold
    /// (skep #857), or at the pending → chain change, the board's file
    /// first read then, the pending file left as it stands with every line
    /// on it (skep #858). The `path` is the native side's: read by
    /// [`Holds::halted_file`] and said in the shell's own window by
    /// [`Holds::show_halted`], it crosses the bridge never (§4b.3; SP-15).
    Halted { path: PathBuf, why: HaltWhy },
}

/// The most inserts a principal's landed-insert record keeps at one board.
///
/// It is the newest kept, as the follower table keeps a session's newest
/// answered bursts (`shell::follow`'s `BURSTS_KEPT`, the same figure): an
/// anchor names a burst of the page's last few, the board committing one at
/// a time (§7b), so a burst whose words a page still names is among them
/// (SP-17).
const LANDED_INSERTS_KEPT: usize = 64;

/// An insert of the principal's kept at the board, as an anchor names it.
///
/// It is its document, the `id` its frame carried, the first I-address its
/// words were minted at — its ack's, or the one the resend's read found
/// (`Holds::minted_at`) — and the positions its values seat
/// (`wire::values_of`): what a piece of a later burst's anchors resolves
/// against once the burst is no longer held ([`Holds::place_anchors`];
/// skep #969).
#[derive(Debug)]
struct LandedInsert {
    doc: String,
    id: String,
    addr: String,
    positions: u64,
}

/// What the person's `send` on a moved document acknowledged of a line.
///
/// It is §3c.4's acknowledgment (skep #757, #989): `through`, the position
/// the board's verdict read through, whose rows the person has seen; and
/// `from`, the position the face that `send` acknowledged read its hands
/// from, where a burst the board refuses again with no row since reads them
/// again ([`Holds::hands_since_typed_state`]). `from` stands below `through`
/// wherever the verdict's typed state does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seen {
    through: u64,
    from: u64,
}

/// One principal's hold at one board.
///
/// It holds where its lines are kept, the queue, the principal's ONE
/// ORDINAL SPACE ([`PrincipalHold::next_k`]), the position of its latest
/// write per document whose position the shell knows — the greatest of its
/// acks', a restore's among them, and of the landings the resend's read
/// found, each noted by
/// [`PrincipalHold::note_position`]: the `base` a hold on that document
/// takes ([`PrincipalHold::base_of`], §3c.2), the position the resend's
/// read of the line starts from, read before the burst's dial so an ack
/// read during the dial never lifts it past the line's own landing — the
/// position of its latest ARRANGEMENT write per document, the one a merge's
/// undo is typed against ([`PrincipalHold::last_arranged`]), the
/// reissues each line's resend has been given and its clock, its first
/// failed send and its last failure's token, kept across its probes
/// ([`Reissues`]), the lines a send has out for its dials
/// ([`PrincipalHold::dialing`]) and the lines marked `sent` no dial of
/// which may have left the device ([`PrincipalHold::never_left`]), the
/// position each line's moved document was acknowledged through by the
/// person's `send` and the one the face it acknowledged was read from
/// ([`PrincipalHold::seen_through`]), the documents the drain's pass has
/// stopped at ([`PrincipalHold::stopped_in_pass`]) and the one the board's
/// silence cut it at ([`PrincipalHold::cut_in_pass`]), the shifts the
/// board's silence left untried ([`PrincipalHold::shift_owed`]) and the
/// moved documents whose hands it left unread
/// ([`PrincipalHold::hands_owed`]), each moved document's shift test
/// ([`PrincipalHold::shift_tests`]), its newest inserts kept with an `id`
/// whose words a burst's anchors may name ([`PrincipalHold::landed_inserts`];
/// skep #969), and whether the wait for the copies its file owes was said
/// ([`PrincipalHold::waiting_said`]). An ack touches no standing line's
/// base: a line held keeps the base it was held at, raised only behind a
/// line kept on its document (`HeldQueue::done`) and by the person's `send`
/// on a moved document (`HeldQueue::remark_all`, [`Holds::resolve`]).
#[derive(Debug)]
struct PrincipalHold {
    custody: Custody,
    /// The account the principal's session named, for the file's header.
    ///
    /// It is the session's at the hold's first touch — the one
    /// [`Holds::principal_hold`] opens the file under — and what the join
    /// opens the board's own file under where the lines were held before the
    /// directory was this shell's; `""` where the board answered none.
    account: String,
    queue: HeldQueue,
    /// The next ordinal a line of the principal's takes.
    ///
    /// It is the one ordinal space per (board, principal), kept for the
    /// shell's life (skep #856; `held`'s THE ORDINALS). Every queue the
    /// principal's lines can be in — memory, the pending file, the board's
    /// own file — draws from it ([`PrincipalHold::hold`]), so an ordinal is
    /// assigned once and names one line until that line leaves: the ordinal
    /// a call holds across its dial, its shift's read or the hands' read, or
    /// the page holds off an `op` answer or `held(session)`, names the line
    /// it held or none, whatever join runs meanwhile (I13). It starts at the
    /// principal's first touch ([`Holds::principal_hold`]) past the greatest
    /// ordinal in every file the principal's lines can be in that the shell
    /// can name then — the origin-named pending file, and the board's own
    /// file where its head has named a chain — and moves past every file the
    /// hold takes after; it is never wound back, not at the compaction, which
    /// removes the file and lets the ordinals run on (`held::MAX_ORDINAL`
    /// states why the space is not at risk). Every ordinal this run gave out,
    /// the settled lines' as well as the standing ones', is below it, so the
    /// one renumbering left — of lines no one was ever answered, an earlier
    /// run's file's, as this run reads them after the first touch — takes a
    /// file holding a line below it past it ([`PrincipalHold::renumbers`];
    /// [`Holds::open_queue`]).
    next_k: u64,
    /// Whether the first touch has set `next_k` past every file the shell
    /// could name then ([`Holds::principal_hold`]).
    touched: bool,
    last_acked: HashMap<String, u64>,
    /// The position of the principal's latest arrangement write per
    /// document that the shell knows (`merge.undo`; P3).
    ///
    /// It is the greatest of the acks of the writes that change a
    /// document's arrangement — the five bursts and `set_arrangement`, each
    /// on its `doc` (wire.md §Arrangement, the typed state), through `op` or
    /// as a restore ([`Holds::note_restored`]) — and of the
    /// landings the resend's read found, each a burst's, noted by
    /// [`PrincipalHold::note_arranged`] and never lowered: the position the
    /// editor's undo of a merge landed in the document is typed against
    /// ([`Holds::last_arranged`]). A link write homed in the document and a
    /// mint change no arrangement and note nothing here, though each raises
    /// `last_acked`, the hold's base. In memory, for the shell's life.
    last_arranged: HashMap<String, u64>,
    reissues: HashMap<u64, Reissues>,
    /// The lines a send has taken for its dials (§3c.4; skep #983).
    ///
    /// Each stands here from the lock that takes it to the send's return or
    /// unwinding ([`LineOut`]): the resend's send of the line (`resend`'s
    /// `send_line`), or a first dial's shift within its call
    /// ([`Holds::shift_at_first_dial`]). No person's act takes a line here
    /// ([`resolvable`]): the send's answer acts on it. In memory.
    dialing: HashSet<u64>,
    /// The lines marked `sent` no write of which may have landed (skep #983).
    ///
    /// A resend marks its line `sent` before each dial, synced, whatever the
    /// dial then answers (§3c.2). A line enters here as a send that took it
    /// ends ([`LineOut`]), where it stood here or was `sent: false` as the
    /// send took it, and every dial of it in that send was answered with a
    /// write that committed nothing — a connection never made, a refusal, a
    /// reissue-class answer, the board's verdict on the typed state, the
    /// death signal (`Dialed::may_have_landed`); it leaves as the next send
    /// takes it, and where it leaves the queue. A line here has not landed
    /// ([`PrincipalHold::may_have_landed`]): a drop reads for no landing of
    /// it and names it among no lines that may have landed. In memory: the
    /// held file keeps the line's `sent`, and no copy undoes it, so a
    /// relaunch forgets the set and the line's drop counts it as one that
    /// may have landed.
    never_left: HashSet<u64>,
    /// What the person's `send` acknowledged of each line's moved document,
    /// by the line's ordinal (§3c.4; skep #757, #989).
    ///
    /// It is set at the person's `send` on a moved document for each line
    /// it re-marks ([`Seen`]): the position the board's verdict read through
    /// — the one the line's `base` is raised to ([`Holds::resolve`]) — and
    /// the position the face that `send` acknowledged read its hands from
    /// ([`PrincipalHold::acknowledged`]); taken out where the line leaves the
    /// queue, as its reissues are ([`Holds::done_line`]). The hands a moved
    /// face names are read since the first where it stands past the burst's
    /// typed state ([`Holds::hands_since_typed_state`]): the rows the person
    /// acknowledged are named no more, save where no row has landed since,
    /// the board refusing the burst again for the change the person
    /// acknowledged, and the hands are read again from the second, named
    /// `again`. Never the line's `base`, which can stand past a burst's
    /// typed state for reasons of its own — an ack, a line kept before it —
    /// and would drop real hands from a first moved face. In memory, as the
    /// clock is: a relaunch forgets it, and the first face after one names
    /// every hand since the typed state, not named `again`, while the raised
    /// `base` persists.
    seen_through: HashMap<u64, Seen>,
    /// The documents the drain's pass has stopped at (§3c.5; skep #817).
    ///
    /// A pass is one walk over the principal's lines in `k` order, cut into
    /// turns of at most [`TURN_STEPS`] steps (`resend`'s turns). A document
    /// whose head the walk does not send — awaiting the person's act, held
    /// `head_unreadable` while the head will not read, read and left
    /// undecided, handed to the person — or whose line's send stops it is
    /// entered here, and every later turn of the pass passes over it, so no
    /// later turn of one pass reads it or dials its head again; a send stops
    /// its document where the turn has no step left for its next shift too
    /// (skep #862). The set is cleared as the pass ends: at a turn no bound
    /// stopped, or a probe that runs no walk ([`BoardHold::end_pass`]). The
    /// person's `send` takes its document out, so the lines it hands back go
    /// at the pass's next turn ([`Holds::resolve`]). In memory.
    stopped_in_pass: HashSet<String>,
    /// The documents the board's silence cut the drain's pass at (§3c.5).
    ///
    /// A request the walk made at a document — its read, a line's send, its
    /// shift's read or its read of the hands — that the board gave no answer
    /// to ends the pass there ([`Turn::Unanswered`]), and the document is
    /// entered here. The turn after it walks every document of every
    /// principal the pass did not reach first, the documents here passed
    /// over, and these last, taken out of the set as that last walk begins
    /// (`resend`'s rounds), so a document whose line keeps going unanswered
    /// while the board answers its probe never holds back another's words.
    /// Cleared with [`PrincipalHold::stopped_in_pass`] as the pass ends, and
    /// the person's `send` takes its document out. In memory.
    cut_in_pass: HashSet<String>,
    /// The shifts the board's silence left untried, by the line's ordinal.
    ///
    /// They are §3c.5's THE SHIFT (2)'s.
    ///
    /// The board refused the line as typed against an older state, and the
    /// shift's live read went unanswered — or a read its attest's composer
    /// made did: the shift was not tried, the line held `unreachable` and
    /// its verdict kept here, so its next send runs the shift from it, no
    /// stale frame dialed first (`resend`'s `send_line`). Taken out as the
    /// shift runs, and where the line leaves the queue
    /// ([`Holds::forget_settled`]). In memory, as the clock is: a relaunch
    /// forgets it, and the line's send meets the board's refusal again.
    shift_owed: HashMap<u64, KeptShift>,
    /// The moved documents whose hands went unread (§3c.5).
    ///
    /// Each names the line the board's verdict rides.
    ///
    /// The moved face stands on the verdict, its hands said not read
    /// ([`Hand::UNREAD`]): their read went unanswered or was answered with no
    /// page, or, where a person's drop, a landing or the held list owed them
    /// ([`Holds::say_with_hands`], [`Holds::lines`]; skep #960, #972, #973),
    /// met the death signal or was not made. The walk reads them again as it
    /// meets the document, and says the moved face once more with the hands
    /// it reads under its own session and under every other session of the
    /// principal's told or listed them not read; a principal no session of
    /// which may write has them read so at each pass (`resend`'s
    /// `reread_hands`). Taken out once every such read has named them, or
    /// named them `unknowable` ([`Hand::UNKNOWABLE`]) — the board has
    /// reclaimed the history, and no read can name them (skep #989) — where
    /// the document is moved no more, and where its line leaves the queue. A
    /// face naming them `unknowable` owes none. In memory.
    hands_owed: HashMap<String, u64>,
    /// Each moved document's shift test, by the document (§3c.5; skep #867).
    ///
    /// It is what a `send` of the document's head would do now, the head's
    /// `sendable`: entered as the moved hold tested the line, and by the walk
    /// where the head owes a test ([`PrincipalHold::shift_test_owed`]). Taken
    /// out where the person's `send` hands the document back and where its
    /// line leaves the queue. In memory: a relaunch owes a first test.
    shift_tests: HashMap<String, ShiftTest>,
    /// The documents a line of which was answered `unwritable` (skep #860).
    ///
    /// Each is entered as the `held` answer says so ([`Holds::enter_line`])
    /// and taken out by the probe that finds no line of it waiting for a
    /// first copy, the document said again ([`Holds::say_landed`]). In
    /// memory, as every line it names is.
    unwritable_docs: HashSet<String>,
    /// The principal's newest inserts kept with an `id`, oldest first
    /// ([`LandedInsert`]; skep #969).
    ///
    /// Each is entered as its ack is noted ([`Holds::note_ack`]) or its
    /// landing found with the address its words were minted at
    /// (`resend`'s `keep_landing`), a later one of the same document and `id`
    /// taking the earlier one's place, and the record keeps the newest
    /// [`LANDED_INSERTS_KEPT`]. A burst's anchors that name the words of a
    /// burst no longer held are placed from it at the burst's door
    /// ([`Holds::place_anchors`]). In memory, as the follower table is: a
    /// relaunch forgets it.
    landed_inserts: VecDeque<LandedInsert>,
    /// Whether the shell's own window was told the queue's file owes copies.
    ///
    /// It is set as the wait is said to begin, and cleared as its end is
    /// ([`Holds::note_waiting`]).
    waiting_said: bool,
    /// Whether the shell's own window was told the pending file the queue's
    /// file took its lines from could not be removed.
    ///
    /// It is set as the refusal is said, and cleared as the file goes
    /// ([`Holds::note_waiting`]).
    superseded_said: bool,
}

impl PrincipalHold {
    /// Returns a hold not yet opened: its queue over `principal`'s file in
    /// the pending directory `pending`, not yet read, its header to name
    /// `account`.
    ///
    /// The file is the pending one until the door reads the principal's file
    /// where the store stands (`Holds::settle_queue`): a line held before
    /// then — the device refusing the store — waits in memory, owed to the
    /// file the door opens.
    fn new(account: &str, pending: &HeldDir, principal: u64) -> PrincipalHold {
        PrincipalHold {
            custody: Custody::Unopened,
            account: account.to_string(),
            queue: HeldQueue::unopened(pending, principal, account),
            next_k: 1,
            touched: false,
            last_acked: HashMap::new(),
            last_arranged: HashMap::new(),
            reissues: HashMap::new(),
            dialing: HashSet::new(),
            never_left: HashSet::new(),
            seen_through: HashMap::new(),
            stopped_in_pass: HashSet::new(),
            cut_in_pass: HashSet::new(),
            shift_owed: HashMap::new(),
            hands_owed: HashMap::new(),
            shift_tests: HashMap::new(),
            unwritable_docs: HashSet::new(),
            landed_inserts: VecDeque::new(),
            waiting_said: false,
            superseded_said: false,
        }
    }

    /// Returns how many sends have taken line `k` for their dials.
    ///
    /// It is [`Reissues::outs`], 0 where no send has.
    fn outs(&self, k: u64) -> u64 {
        self.reissues.get(&k).map_or(0, |given| given.outs)
    }

    /// Returns whether line `k`, held for `reason`, may have landed.
    ///
    /// It may where a dial of it may have left this device: it is marked
    /// `sent`, and is not among the lines no dial of which left
    /// ([`PrincipalHold::never_left`]). It is the one test a drop reads first
    /// by ([`reads_first`]) and names its lines by ([`Holds::drop_run`];
    /// skep #983, #993).
    fn may_have_landed(&self, k: u64, reason: &Reason) -> bool {
        reason.sent && !self.never_left.contains(&k)
    }

    /// Returns what the person's `send` acknowledges of line `judged`'s
    /// moved face ([`Seen`]; §3c.4; skep #757, #989).
    ///
    /// `through` is the position the line's verdict read through and `typed`
    /// the typed state the verdict echoes. The face was read from the later
    /// of `typed` and the position an earlier `send` acknowledged the line
    /// through — save where no row has moved the document past that earlier
    /// position, the face then naming again the hands the earlier `send`
    /// acknowledged, read from where that one's were; a verdict with no
    /// typed state named no hands, and leaves nothing to read again.
    fn acknowledged(&self, judged: u64, through: u64, typed: Option<u64>) -> Seen {
        let earlier = self.seen_through.get(&judged).copied();
        let from = match (earlier, typed) {
            (Some(earlier), _) if earlier.through >= through => earlier.from,
            (earlier, Some(typed)) => earlier.map_or(typed, |earlier| earlier.through.max(typed)),
            (_, None) => through,
        };
        Seen { through, from }
    }

    /// Notes an insert of the principal's kept at the board, its words
    /// minted from `minted` ([`PrincipalHold::landed_inserts`]; skep #969).
    ///
    /// `frame` is the insert as it was sent. An insert with no `id`, or one
    /// past [`MAX_BURST_ID_BYTES`], or whose values are not the wire's forms,
    /// is no burst a page's anchors can name, and nothing is noted; an earlier
    /// insert of the same document and `id` is let go, the newest the one a
    /// piece names.
    fn note_landed_insert(&mut self, frame: &Value, minted: &str) {
        let (Some(doc), Some(id)) = (frame["doc"].as_str(), frame["id"].as_str().filter(|id| id.len() <= MAX_BURST_ID_BYTES)) else { return };
        let Ok(values) = values_of(&frame["values"]) else { return };
        self.landed_inserts.retain(|landed| landed.doc != doc || landed.id != id);
        if self.landed_inserts.len() == LANDED_INSERTS_KEPT {
            self.landed_inserts.pop_front();
        }
        self.landed_inserts.push_back(LandedInsert { doc: doc.to_string(), id: id.to_string(), addr: minted.to_string(), positions: values.len() as u64 });
    }

    /// Returns the newest insert of the principal's kept on `doc` with `id`,
    /// where the record keeps one ([`PrincipalHold::landed_inserts`]).
    fn landed_insert(&self, doc: &str, id: &str) -> Option<&LandedInsert> {
        self.landed_inserts.iter().rev().find(|landed| landed.doc == doc && landed.id == id)
    }

    /// Returns whether the resend walks the hold's lines: some stand, and
    /// the principal is not halted — no line is sent once a halt stands,
    /// wherever it is stored (P38; skep #858).
    fn drains(&self) -> bool {
        !self.queue.is_empty() && !matches!(self.custody, Custody::Halted { .. })
    }

    /// Holds a line under the principal's next ordinal (`HeldQueue::hold`).
    ///
    /// The counter moves past the ordinal where the queue takes the line,
    /// and stands where it refuses it: the one place an ordinal is handed
    /// out ([`PrincipalHold::next_k`]).
    ///
    /// # Errors
    ///
    /// Returns what the queue refuses (`held::Unheld`), nothing held.
    fn hold(&mut self, doc: &str, id: Option<&str>, base: u64, frame: Value, anchors: Option<Anchors>, reason: Reason) -> Result<Entered, Unheld> {
        let entered = self.queue.hold(self.next_k, doc, id, base, frame, anchors, reason)?;
        // The ordinal is within `MAX_ORDINAL`, so its successor is a `u64`.
        self.next_k = entered.k + 1;
        Ok(entered)
    }

    /// Takes a file's queue as the principal's, this run's standing lines
    /// entered into it, and returns what entered.
    ///
    /// `file` is the file as the door read it — the pending one, or the
    /// board's own, its lines below the counter renumbered past it first
    /// ([`PrincipalHold::renumbers`]) — and the hold's queue is the one it
    /// replaces: the queue the hold kept while the file could not be read,
    /// or the pending file's queue at the pending → chain change. Every
    /// line of this run's enters under its own ordinal, owed its first copy
    /// to the file, and the retry writes them (`HeldQueue::join`); the
    /// counter moves past every ordinal the file names. The queue replaced
    /// is answered beside, for its file's removal once no copy is owed.
    fn take(&mut self, file: HeldQueue) -> (Joined, HeldQueue) {
        let ours = std::mem::replace(&mut self.queue, file);
        let joined = self.queue.join(&ours, Joining::ThisRun);
        // The greatest is within `MAX_ORDINAL`, so its successor is a `u64`.
        self.next_k = self.next_k.max(self.queue.greatest_k() + 1);
        self.custody = Custody::File;
        (joined, ours)
    }

    /// Returns whether `file` takes fresh ordinals before the hold takes it.
    ///
    /// `file` is read now and is not the hold's own queue: the door takes it
    /// ([`PrincipalHold::take`]; `HeldQueue::renumber`; skep #875). It takes
    /// them where it holds a line under an ordinal below the counter
    /// ([`PrincipalHold::next_k`]), which is past every ordinal this run gave
    /// out, the settled lines' as well as the standing ones': kept, such a
    /// line would take an ordinal a call or the page may hold (I13), or walk
    /// ahead of this run's lines, which a file read after the first touch
    /// walks after (`held`'s THE ORDER). A file whose lines all stand at or
    /// past the counter keeps its ordinals, none of them given out and every
    /// line already walking after this run's; at the first touch the counter
    /// is fresh, so the file the door reads then keeps its own.
    fn renumbers(&self, file: &HeldQueue) -> bool {
        file.first_k().is_some_and(|first| first < self.next_k)
    }

    /// Notes `at`, the position of a write of the principal's on `doc`.
    ///
    /// It is the document's `base` from here where it is past the position
    /// noted there, which stands otherwise (§3c.2). Answers are noted in the
    /// order they are read, not the order the board committed them — a
    /// call's on its connection's thread, a resend's and a landing the
    /// resend's read found on the board's feed thread — so an earlier write
    /// read after a later one never lowers the base below that later write,
    /// whose row the next hold's read would otherwise read again.
    fn note_position(&mut self, doc: &str, at: u64) {
        let base = self.last_acked.entry(doc.to_string()).or_insert(at);
        *base = (*base).max(at);
    }

    /// Notes `at`, the position of an arrangement write of the principal's
    /// on `doc` ([`PrincipalHold::last_arranged`]).
    ///
    /// It stands from here where it is past the position noted there, as
    /// [`PrincipalHold::note_position`]'s does: an earlier write read after
    /// a later one never lowers it.
    fn note_arranged(&mut self, doc: &str, at: u64) {
        let last = self.last_arranged.entry(doc.to_string()).or_insert(at);
        *last = (*last).max(at);
    }

    /// Returns the `base` a line held on `doc` takes now (§3c.2).
    ///
    /// It is the position of the principal's latest write on `doc` that the
    /// shell knows — its ack's, or the landing the resend's read found — or
    /// else `opened_at`, the open position of the session the line is held
    /// under. A burst's send reads it before its dial ([`Holds::send_burst`]).
    fn base_of(&self, doc: &str, opened_at: u64) -> u64 {
        self.last_acked.get(doc).copied().unwrap_or(opened_at)
    }

    /// Returns how many lines stand on `doc`.
    ///
    /// It is read off the queue's entry for it (`HeldQueue::count_on`),
    /// walking no line.
    fn count(&self, doc: &str) -> u64 {
        self.queue.count_on(doc) as u64
    }

    /// Returns how many lines stand on `doc` and why one has no copy on disk.
    ///
    /// The why is the refusal of the copy the retry stopped at, absent where
    /// every line of `doc` has a copy (`HeldQueue::waits_on`).
    fn lines_on(&self, doc: &str) -> LinesOn {
        let waiting = self.queue.waiting().filter(|_| self.queue.waits_on(doc));
        LinesOn { held: self.count(doc), unwritable: waiting.map(|waiting| Unwritable::from(&waiting.refusal())) }
    }

    /// Returns the verdict `doc` stands moved on now, where it stands on one.
    ///
    /// It is the one its first line carries ([`Judged::of`]; skep #973).
    fn judged_on(&self, doc: &str) -> Option<Judged> {
        let (k, reason) = self.queue.reasons_on(doc).next()?;
        Judged::of(k, reason)
    }

    /// Returns `doc`'s first line's ordinal where it awaits the person's act.
    ///
    /// It is a refused run's line or a moved document's ([`awaits_act`]) that
    /// no send has out for its dials ([`PrincipalHold::dialing`]): a first
    /// dial's shift enters its line `moved`, tells no one of it while its call
    /// settles it, and no act of the person's takes it meanwhile
    /// ([`resolvable`]). While such a line stands, every `held` event of `doc`
    /// says its state, the lines behind it changing the count alone (§3c.4,
    /// §4b.2; skep #974).
    fn first_awaiting_act(&self, doc: &str) -> Option<u64> {
        let (k, reason) = self.queue.reasons_on(doc).next()?;
        (awaits_act(reason) && !self.dialing.contains(&k)).then_some(k)
    }

    /// Returns whether line `k` stands moved at the head of `doc`.
    fn heads_moved(&self, doc: &str, k: u64) -> bool {
        self.queue.reasons_on(doc).next().is_some_and(|(head, reason)| head == k && reason.cause == cause::MOVED)
    }

    /// Returns whether `head`, its document's head, owes a shift test.
    ///
    /// A moved head owes one where it has no answer of its own — a line held
    /// past its deadline, a relaunch — or where its answer stands stale.
    fn shift_test_owed(&self, head: &HeldLine) -> bool {
        head.reason.cause == cause::MOVED && self.shift_tests.get(&head.doc).is_none_or(|test| test.k != head.k || test.stale)
    }

    /// Enters what the shift test answered of `doc`'s head, line `k`.
    ///
    /// It answers whether it entered it: nothing is entered where that line
    /// no longer stands moved at the head. What the page was last told
    /// stands.
    fn note_tested(&mut self, doc: &str, k: u64, answer: Tested, stale: bool) -> bool {
        let entered = self.heads_moved(doc, k);
        if entered {
            let told = self.told_live(doc, k);
            self.shift_tests.insert(doc.to_string(), ShiftTest { k, answer, stale, told });
        }
        entered
    }

    /// Returns whether the last `moved` event held the act live on line `k`.
    fn told_live(&self, doc: &str, k: u64) -> bool {
        self.shift_tests.get(doc).is_some_and(|test| test.k == k && test.told)
    }

    /// Returns the `sendable` a `moved` event of `doc` says now.
    ///
    /// The answer is told from here: what the page was last told follows it.
    fn sendable_told(&mut self, doc: &str) -> Option<bool> {
        let test = self.shift_tests.get_mut(doc)?;
        test.told = test.answer.live();
        test.answer.sendable()
    }

    /// Returns the `sendable` `line`'s row carries, where it carries one.
    ///
    /// It carries one where the line stands moved, the test's answer is its
    /// own — the document's first moved line alone — and the shell knows.
    fn sendable_of(&self, line: &HeldLine) -> Option<bool> {
        if line.reason.cause != cause::MOVED {
            return None;
        }
        self.shift_tests.get(&line.doc).filter(|test| test.k == line.k).and_then(|test| test.answer.sendable())
    }
}

/// Whether a board answers, as the hold judges it (§3c.4's THE END, §3c.5).
///
/// A `/health` read is the one judge: one the board gave no answer to is its
/// silence, any answer the board answering ([`Holds::note_health_read`]). A
/// request of the hold's the board gave no answer to holds the board's
/// writes until that verdict ([`Holds::note_unanswered`]).
#[derive(Debug)]
enum Answering {
    /// The board answers.
    ///
    /// No request of the hold's has gone unanswered since a `/health`
    /// answered.
    Answers,
    /// A request of the hold's went unanswered at `since`; a verdict pends.
    ///
    /// The verdict is the next `/health`'s.
    ///
    /// Nothing more of the hold's is dialed at the board meanwhile: a burst
    /// is held at once, and the drain walks no line. `cut` holds the sends
    /// the board gave no answer to whose request may have left, each a
    /// failed send of its line at its own instant where the verdict finds the
    /// board answering — the line's own failure — and none where it finds the
    /// board silent.
    Unanswered { since: Instant, cut: Vec<CutSend> },
    /// A `/health` went unanswered: the board's silence, from `since`.
    ///
    /// The silence runs from the first request the board gave no answer to,
    /// where one came before the verdict.
    ///
    /// Every burst is held `unreachable` at once, and the board's answering
    /// clock stands still ([`BoardHold::answering_at`]).
    Silent { since: Instant },
}

/// A send of a held line the board gave no answer to.
///
/// Its failure is owed to the next `/health` verdict
/// (`Answering::Unanswered`).
#[derive(Debug)]
struct CutSend {
    principal: u64,
    k: u64,
    doc: String,
    /// The instant the send was cut, its failure's where it is one.
    at: Instant,
    /// The dial's refusal as the shell's own window says it.
    refusal: String,
}

/// A shift the board's silence left untried (`PrincipalHold::shift_owed`).
///
/// It is the board's refusal of the line as typed against an older state, as
/// its dial read it: the moved reason, the verdict on it, and the refusal.
#[derive(Debug, Clone)]
struct KeptShift {
    reason: Reason,
    refusal: Refusal,
}

/// One board's hold.
///
/// It holds its directory, the three states that hold every burst before
/// any dial — and refuse the unholdable writes at once — whether the board
/// answers and its answering clock, the positions this shell acked at the
/// board, the causes last said of lines kept from their files, the key
/// labels read for each account, and each principal's queue.
#[derive(Debug)]
struct BoardHold {
    directory: Directory,
    /// The chain the board's head last named, where a read answered a term
    /// ([`Holds::establish`]); `None` until one does.
    ///
    /// It names the board's own held file where the directory is not this
    /// shell's — refused, or another shell's — so a principal's first touch
    /// can read the file's greatest ordinal ([`Holds::principal_hold`]).
    chain: Option<Chain>,
    /// The positions this shell acked at the board (§3c.5).
    ///
    /// Every ack [`Holds::note_ack`] reads enters its `at`, whatever
    /// documents its row names, and every restore [`Holds::note_restored`]
    /// notes and every landing the resend's read finds enter their
    /// positions; in memory, for the shell's life. The resend's
    /// landed test skips a row at one of them: a write this shell was
    /// answered for is never the lost landing of a line, though its hand is
    /// the same key and its kind the head's — a sibling session's burst
    /// through this hold, or the person's own write on another connection
    /// acked while the line's dial was out (skep #737). What it cannot hold,
    /// named: a row of the same key not through this shell — the `skep`
    /// command's, which dials the board itself — stays a candidate for a
    /// landing of the same kind; and a relaunch starts the set empty, so a
    /// row an earlier run acked is a candidate again. No bound is kept: a
    /// position is of no further use only once no line held later can read
    /// from below it, and a line's base — its principal's last acked
    /// position on its document, else its session's open — can lie below
    /// any acked position for the shell's life; the set grows by one `u64`
    /// per ack, a few megabytes over a day of a write a second, and dies
    /// with the shell.
    acked: HashSet<u64>,
    /// Whether the last read of `/health.writes.halted` answered true.
    ///
    /// The read is the feed's tick's, or the probe's: every burst holds
    /// `halted` without a dial until a read answers false, which only a
    /// restart makes it (§3c.4; wire.md §The other endpoints).
    writes_halted: bool,
    /// Whether a dial at this board answered `poisoned` since the last
    /// `/health` read that said writes go.
    ///
    /// The board's write path halted inside a commit (wire.md §Rejection
    /// codes): every write after it is refused `poisoned` until the board
    /// restarts, so the unholdable writes are refused here without a
    /// dial, `poisoned` their cause, from the first such answer until a
    /// `/health` read answers `writes.halted` false (§3c.4).
    poisoned: bool,
    /// Whether the own node is stopped by the person's act.
    ///
    /// While it is, every burst holds `stopped` without a dial, and the
    /// probe dials nothing until `set_node_state(Running)` clears it
    /// (§3c.4).
    node_stopped: bool,
    /// The board's head as the hold last read it ([`Holds::note_head`]).
    head: HeadState,
    /// The board's state as it was last told ([`Holds::state_change`]).
    ///
    /// It is `Running` until a change is told: a board that answers and
    /// holds nothing is announced nothing.
    told: BoardState,
    /// Whether the board answers ([`Answering`]).
    ///
    /// It is the last `/health` verdict and the requests of the hold's since.
    answering: Answering,
    /// The answering clock's zero: the instant the hold was made.
    ///
    /// The clock is [`BoardHold::answering_at`].
    clock_zero: Instant,
    /// The board's silences closed so far, summed.
    silences: Duration,
    /// The cause last said in the shell's own window of each principal's
    /// lines kept from its file, by principal (SP-11, SP-12).
    ///
    /// It is the device's refusal of the file's read at the door, or of the
    /// renumbering copy the read owed, said where it is not the one standing
    /// here ([`Holds::say_kept_from_file`]) and never at each probe's retry,
    /// and it goes as the file opens, saying so.
    kept_said: HashMap<u64, String>,
    /// The cause last said of the store a try could not take — the device
    /// refusing the pending directory or its lock, or the board's own —
    /// said once per change, and gone once the store is this shell's
    /// ([`Holds::say_store`]).
    store_said: Option<String>,
    /// The key labels read for each account (`labels`; skep #869).
    ///
    /// It is kept for the shell's life, by the account the read was made for.
    labels: HashMap<String, AccountLabels>,
    principals: HashMap<u64, PrincipalHold>,
}

impl BoardHold {
    /// Returns the board's state: the most severe that holds (skep #865).
    ///
    /// The order is the own node stopped, the board's silence, its writes
    /// halted, its head record not reading, else running (§4b.2; P37). A
    /// request of the hold's unanswered, its verdict pending, is no silence
    /// yet, and a `poisoned` answer is a halt from the `/health` read after
    /// it.
    fn state(&self) -> BoardState {
        if self.node_stopped {
            BoardState::Stopped
        } else if self.silent() {
            BoardState::Unreachable
        } else if self.writes_halted {
            BoardState::Halted
        } else if let HeadState::Unreadable(cause) = &self.head {
            BoardState::HeadUnreadable(cause.clone())
        } else {
            BoardState::Running
        }
    }

    /// Returns whether a probe owes the board a read with no signed session.
    ///
    /// It does while a line stands to drain, while the board is silent or a
    /// request of the hold's there pends its verdict, and while its writes
    /// stand halted or its head unreadable, so a state told can clear with
    /// no session left to ask.
    fn probe_owed(&self) -> bool {
        !self.answers() || self.writes_halted || matches!(self.head, HeadState::Unreadable(_)) || self.principals.values().any(PrincipalHold::drains)
    }

    /// Returns the cause of the hold that stands at the board, where one does.
    ///
    /// It is §3c.4's order — the own node stopped, else the write path
    /// poisoned, else the writes halted — the token a burst is held under and
    /// an unholdable write refused with.
    fn standing_cause(&self) -> Option<&'static str> {
        if self.node_stopped {
            Some(cause::STOPPED)
        } else if self.poisoned {
            Some(cause::POISONED)
        } else if self.writes_halted {
            Some(cause::HALTED)
        } else {
            None
        }
    }

    /// Returns why no read for a line's landing is made at the board now.
    ///
    /// It is the drop's check before its read (§3c.4; skep #866), and none
    /// where the read is made: a hold stands — the own node stopped, the
    /// write path poisoned, the writes halted, in that order, a restart of a
    /// halted board rebuilding from its journal a landing no read sees yet —
    /// or the board is not answering, nothing more of the hold's dialed there
    /// until a `/health` answers (§3c.5).
    fn landing_unreadable(&self) -> Option<LandingUnread> {
        match self.standing_cause() {
            Some(cause::STOPPED) => Some(LandingUnread::Stopped),
            Some(cause::POISONED) => Some(LandingUnread::Poisoned),
            Some(_) => Some(LandingUnread::Halted),
            None => (!self.answers()).then_some(LandingUnread::Unanswered),
        }
    }

    /// Returns the file P38 halted for `principal` at the board, and why.
    ///
    /// It is the principal's custody where that is the halt
    /// ([`Custody::Halted`]), and none otherwise.
    fn halted(&self, principal: u64) -> Option<(&Path, HaltWhy)> {
        match &self.principals.get(&principal)?.custody {
            Custody::Halted { path, why } => Some((path, *why)),
            Custody::Unopened | Custody::File => None,
        }
    }

    /// Returns the board's answering clock at `at` (§3c.4's bound; skep #863).
    ///
    /// It is the time since the hold was made less every silence of the
    /// board's, one still open counted from its start to `at` — a request
    /// pending its verdict counting as answering until the verdict is silence,
    /// which counts the silence from that request then. A line's two minutes
    /// are read off it ([`HAND_OVER_DEADLINE`]), so they run only while the
    /// board answers, paused across a silence and never reset.
    fn answering_at(&self, at: Instant) -> Duration {
        let open = match self.answering {
            Answering::Silent { since } => at.saturating_duration_since(since),
            Answering::Answers | Answering::Unanswered { .. } => Duration::ZERO,
        };
        at.saturating_duration_since(self.clock_zero).saturating_sub(self.silences.saturating_add(open))
    }

    /// Returns whether the board answers.
    ///
    /// No request of the hold's went unanswered since a `/health` answered.
    fn answers(&self) -> bool {
        matches!(self.answering, Answering::Answers)
    }

    /// Returns whether the last `/health` read found the board silent.
    fn silent(&self) -> bool {
        matches!(self.answering, Answering::Silent { .. })
    }

    /// Returns whether a request of the hold's went unanswered.
    ///
    /// The next `/health` verdict is pending.
    fn pending(&self) -> bool {
        matches!(self.answering, Answering::Unanswered { .. })
    }

    /// Notes a failed send of line `k` of `principal`'s at `at`.
    ///
    /// `token` is its failure's ([`Reissues::failed`]).
    ///
    /// The line's clock reads the instant and the board's answering clock
    /// then. It answers whether `token` differs from the last failure's as it
    /// stood, and true where the principal holds nothing at the board.
    fn note_failure(&mut self, principal: u64, k: u64, token: String, at: Instant) -> bool {
        let moment = Moment { at, answering: self.answering_at(at) };
        self.principals.get_mut(&principal).map(|ph| ph.reissues.entry(k).or_default().failed(token, moment)).unwrap_or(true)
    }

    /// Ends the drain's pass at the board.
    ///
    /// Every document a turn of it stopped at, or the board's silence cut it
    /// at, is walked again by the next pass
    /// ([`PrincipalHold::stopped_in_pass`], [`PrincipalHold::cut_in_pass`]).
    fn end_pass(&mut self) {
        for ph in self.principals.values_mut() {
            ph.stopped_in_pass.clear();
            ph.cut_in_pass.clear();
        }
    }
}

/// One board of the holds: the board dialed, and its hold under its own lock.
///
/// The board is dialed outside any lock; the hold's lock is held for a
/// burst's line, its synced append and a file's read at a session's open,
/// and never across a dial.
#[derive(Debug)]
struct BoardSlot {
    board: Arc<Board>,
    hold: Mutex<BoardHold>,
    /// Whether a turn of a resend drains this board now.
    ///
    /// One drain per board runs at a time, whatever thread reaches
    /// [`Holds::probe`] — the board's feed thread every `PROBE_CADENCE`, at
    /// its daemon-running tick, at the hand-overs of `resolve(send)`, of a
    /// `resolve(drop)` that kept its line and of `set_node_state(Running)`,
    /// and at each turn after one its bound stopped — so none double-sends;
    /// the mark is held for one turn, and only the drain that holds it ends
    /// the pass ([`BoardHold::end_pass`]).
    draining: AtomicBool,
}

impl BoardSlot {
    /// Locks the board's hold: this board's alone.
    ///
    /// # Panics
    ///
    /// Panics where the board's hold lock is poisoned.
    fn lock(&self) -> MutexGuard<'_, BoardHold> {
        self.hold.lock().expect("a board's hold lock")
    }
}

/// A held line a send has taken for its dials (§3c.4; skep #983).
///
/// It is the resend's send of the line (`resend`'s `send_line`), or a first
/// dial's shift within its call ([`Holds::shift_at_first_dial`]), from the
/// lock that takes the line ([`LineOut::take`]) until the send has settled
/// it: the line stands in [`PrincipalHold::dialing`] meanwhile, so no
/// person's act takes it while a dial of it is out, and the send is counted
/// on the line ([`Reissues::outs`]), so a drop whose read was out as the send
/// took the line acts on nothing. The send notes each dial's answer
/// ([`LineOut::answered`]). Dropped once the send has settled the line — and
/// before its face is told, so an act the face asks for takes it — it lets
/// the line out of `dialing`, and into [`PrincipalHold::never_left`] where no
/// dial of it may have left the device, none of the send's and none before
/// it; dropped as the send unwinds, a dial that panics among them, it lets
/// the line out of `dialing` alone, a dial of it unaccounted for.
#[must_use = "the line stands taken until the `LineOut` is dropped"]
struct LineOut<'h> {
    holds: &'h Holds,
    board_reference: &'h str,
    principal: u64,
    k: u64,
    /// Whether no dial of the line may have left the device so far.
    quiet: bool,
}

impl<'h> LineOut<'h> {
    /// Takes line `k` of `ph`, `principal`'s hold at the board, for a send.
    ///
    /// It answers none where no line of `k` stands, nothing taken.
    fn take(holds: &'h Holds, board_reference: &'h str, principal: u64, ph: &mut PrincipalHold, k: u64) -> Option<LineOut<'h>> {
        let sent = ph.queue.reason(k)?.sent;
        let listed = ph.never_left.remove(&k);
        ph.dialing.insert(k);
        ph.reissues.entry(k).or_default().outs += 1;
        Some(LineOut { holds, board_reference, principal, k, quiet: listed || !sent })
    }

    /// Notes the answer one dial of the line met.
    ///
    /// Where its write may have landed ([`Dialed::may_have_landed`]), the
    /// line counts as one that may have landed from here.
    fn answered(&mut self, dialed: &Dialed) {
        self.quiet &= !dialed.may_have_landed();
    }
}

impl Drop for LineOut<'_> {
    /// Lets the line go, and enters it in `never_left` where it stays quiet.
    ///
    /// It enters it only where the send returned, never as it unwinds, and
    /// takes the board's lock poisoned or not, so an unwinding send never
    /// panics here again.
    fn drop(&mut self) {
        let mut board_hold = self.holds.slot(self.board_reference).hold.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(ph) = board_hold.principals.get_mut(&self.principal) else { return };
        ph.dialing.remove(&self.k);
        if self.quiet && !thread::panicking() && ph.queue.reason(self.k).is_some() {
            ph.never_left.insert(self.k);
        }
    }
}

/// The holds: every board's hold, shared by the shell and the feed threads.
///
/// The shell shares it for the `op` row's one path, `held` and `resolve`, a
/// session's open, a ceremony's door and `set_node_state`; the boards' feed
/// threads for the probe, the `/health` read and the daemon-running end. The
/// boards are the shell's, fixed at its open, each under its own lock. A
/// method about a session reaches its board through the session — its
/// `board_reference` the hold's key, its `board` the board dialed — and the
/// board-wide ones (`probe`, `touch_store`, `set_node_stopped`,
/// `node_stopped`, `another_window`, `note_health`, `note_health_read`,
/// `state`, `state_change`) take the board's
/// reference, as `halted_file` and `copies_owed`, the native side's reads of
/// a principal's held file, and `note_rows`, the drafts read's hand-over of
/// the rows it named, take it beside the principal.
///
/// # Panics
///
/// A method panics where its precondition, the caller's, is broken: each
/// reference names a board the holds were opened over — held by
/// construction, a session registered at one of the shell's boards and each
/// feed thread probing its own board; a reference outside them is a bug of
/// this crate's, and the method panics naming the obligation.
pub struct Holds {
    sessions: Arc<Sessions>,
    bus: Arc<EventBus>,
    /// The key store a signed session's attest is signed from.
    ///
    /// The attest is `SessionEntry::attest`'s; the held store is `held`'s
    /// files under `data_dir`.
    key_store: Arc<FileStore>,
    data_dir: PathBuf,
    talk: Talk,
    boards: HashMap<String, BoardSlot>,
    /// The `held` event last emitted per (board, session, document).
    ///
    /// It is what the event said ([`HeldSaid`]; [`Holds::emit_said`]), a
    /// `moved` face's verdict among it, or what the held list named of the
    /// document, which tells no event ([`Holds::remember`]; skep #973).
    ///
    /// The event goes out once per change of a document's state (skep #727): an
    /// emit of what was last emitted for its key is none, so a moved face whose
    /// hands are read at last is said again with them (skep #863), one for
    /// another verdict is said (skep #973), and one naming a line kept is said
    /// whatever was last told (skep #968). A leaf lock, taken inside
    /// `emit_said`, `remember` and `told` alone and never held while another
    /// lock is taken — the emit is made under the board's lock from `resolve`
    /// and a hold among others, so the memory lives beside the boards' locks,
    /// not under one. A document kept with no line left clears its key.
    last_emitted: Mutex<HashMap<HeldKey, HeldSaid>>,
    /// The milliseconds a suite moved the clock forward ([`Holds::now`]).
    ///
    /// It is zero in every shipped build, where nothing moves it.
    skew_ms: AtomicU64,
}

impl Holds {
    /// Returns the holds for a shell over `boards`.
    ///
    /// Each board's entry gives its reference beside the board dialed, the
    /// shell's for its life: nothing is dialed and nothing on disk touched
    /// here — a board's store is first touched by a session's open, a
    /// ceremony's door ([`Holds::touch_store`]) or the board's first probe.
    pub fn new(sessions: Arc<Sessions>, bus: Arc<EventBus>, key_store: Arc<FileStore>, data_dir: PathBuf, talk: Talk, boards: impl IntoIterator<Item = Arc<BoardEntry>>) -> Arc<Holds> {
        let boards = boards
            .into_iter()
            .map(|entry| {
                let hold = BoardHold {
                    directory: Directory::NotYet(io::Error::other("the board's held store is not touched yet")),
                    chain: None,
                    acked: HashSet::new(),
                    writes_halted: false,
                    poisoned: false,
                    node_stopped: false,
                    head: HeadState::Unknown,
                    told: BoardState::Running,
                    answering: Answering::Answers,
                    clock_zero: Instant::now(),
                    silences: Duration::ZERO,
                    kept_said: HashMap::new(),
                    store_said: None,
                    labels: HashMap::new(),
                    principals: HashMap::new(),
                };
                (entry.reference.clone(), BoardSlot { board: Arc::clone(&entry.board), hold: Mutex::new(hold), draining: AtomicBool::new(false) })
            })
            .collect();
        Arc::new(Holds { sessions, bus, key_store, data_dir, talk, boards, last_emitted: Mutex::new(HashMap::new()), skew_ms: AtomicU64::new(0) })
    }

    /// Says `line` on `Talk` as the hold's: `held: ` and the line.
    fn say(&self, line: impl fmt::Display) {
        (self.talk)(&format!("held: {line}"));
    }

    /// Returns the time a line's clock reads ([`HAND_OVER_DEADLINE`]).
    ///
    /// It is the monotonic clock's now, moved forward by what a suite added
    /// (`advance`) — nothing, in every shipped build. Every read of a line's
    /// deadline, and every start of its clock, reads it here.
    fn now(&self) -> Instant {
        let now = Instant::now();
        now.checked_add(Duration::from_millis(self.skew_ms.load(Ordering::Relaxed))).unwrap_or(now)
    }

    /// Moves the clock a line's deadline reads forward by `by`.
    ///
    /// It is the suites' seam: a cell cannot wait two minutes.
    #[cfg(test)]
    pub(crate) fn advance(&self, by: Duration) {
        self.skew_ms.fetch_add(millis(by), Ordering::Relaxed);
    }

    /// Notes a failed send of line `k` of `principal`'s ([`Reissues::failed`]).
    ///
    /// Its clock starts where it stands unstarted, at [`Holds::now`] and the
    /// board's answering clock then, and `token` is the last failure's from
    /// here. It answers whether `token` differs from the last failure's as it
    /// stood.
    fn note_failure(&self, board_reference: &str, principal: u64, k: u64, token: String) -> bool {
        let now = self.now();
        self.lock(board_reference).note_failure(principal, k, token, now)
    }

    /// Returns how long line `k`'s clocks have run since its first failure.
    ///
    /// The last failure's token rides beside, and none is answered where the
    /// line has not failed ([`HAND_OVER_DEADLINE`]).
    fn since_first_failure(&self, board_reference: &str, principal: u64, k: u64) -> Option<(Elapsed, String)> {
        let now = self.now();
        let board_hold = self.lock(board_reference);
        let given = board_hold.principals.get(&principal)?.reissues.get(&k)?;
        let (first, last) = (given.first_failed?, given.last.clone()?);
        let elapsed = Elapsed { answering: board_hold.answering_at(now).saturating_sub(first.answering), wall: now.saturating_duration_since(first.at) };
        Some((elapsed, last))
    }

    /// Notes a request of the hold's the board gave no answer to (§3c.5).
    ///
    /// `board_hold` is the board's. The board answering, it is marked
    /// unanswered from now until the next `/health` verdict
    /// ([`Answering::Unanswered`]) — nothing more of the hold's is dialed
    /// there meanwhile — and `cut`, a send the request was whose dial may
    /// have left, is owed to that verdict; a request already pending a
    /// verdict adds its `cut` to it, and a silent board's owes none, the
    /// silence standing.
    fn note_unanswered(&self, board_hold: &mut BoardHold, cut: Option<CutSend>) {
        match &mut board_hold.answering {
            Answering::Answers => board_hold.answering = Answering::Unanswered { since: self.now(), cut: cut.into_iter().collect() },
            Answering::Unanswered { cut: owed, .. } => owed.extend(cut),
            Answering::Silent { .. } => {}
        }
    }

    /// Notes a `/health` read the board gave no answer to: its silence.
    ///
    /// It is §3c.4's THE END.
    ///
    /// The silence runs from the first request the board gave no answer to
    /// where one pends its verdict, and from now otherwise; a silent board's
    /// stands. The sends a pending request cut owe no failure: the silence
    /// was the board's, never the line's.
    fn note_silence(&self, board_hold: &mut BoardHold) {
        match &board_hold.answering {
            Answering::Answers => board_hold.answering = Answering::Silent { since: self.now() },
            Answering::Unanswered { since, .. } => board_hold.answering = Answering::Silent { since: *since },
            Answering::Silent { .. } => {}
        }
    }

    /// Notes a `/health` read the board answered: the board answers.
    ///
    /// A refusal is an answer (§3c.4's THE END).
    ///
    /// A silence closes, its length taken off the board's answering clock
    /// ([`BoardHold::answering_at`]). A request pending its verdict was its
    /// line's own: each send it cut whose line stands is a failed send of the
    /// line at the send's own instant ([`BoardHold::note_failure`]), said in
    /// the shell's own window where its failure changed, as a resend's
    /// refusal is (SP-11).
    fn note_answering(&self, board_hold: &mut BoardHold) {
        match std::mem::replace(&mut board_hold.answering, Answering::Answers) {
            Answering::Answers => {}
            Answering::Silent { since } => board_hold.silences = board_hold.silences.saturating_add(self.now().saturating_duration_since(since)),
            Answering::Unanswered { cut, .. } => {
                for CutSend { principal, k, doc, at, refusal } in cut {
                    let stands = board_hold.principals.get(&principal).is_some_and(|ph| ph.queue.line(k).is_some());
                    if stands && board_hold.note_failure(principal, k, cause::UNREACHABLE.to_string(), at) {
                        self.say(format_args!("line {k} on {doc} was not taken ({refusal}); it is sent again as the board answers"));
                    }
                }
            }
        }
    }

    /// Returns the board `board_reference` names.
    ///
    /// It is the one place the type's precondition is asked, every method
    /// reaching a board through here.
    ///
    /// # Panics
    ///
    /// Panics where `board_reference` names no board the holds were opened
    /// over.
    fn slot(&self, board_reference: &str) -> &BoardSlot {
        self.boards.get(board_reference).unwrap_or_else(|| panic!("PRECONDITION of `Holds`: `{board_reference}` names a board the holds were opened over"))
    }

    /// Returns the hold of the board `board_reference` names, under its lock.
    fn lock(&self, board_reference: &str) -> MutexGuard<'_, BoardHold> {
        self.slot(board_reference).lock()
    }

    /// Runs `f` over `principal`'s hold at the board, under the board's lock.
    ///
    /// It runs where the principal has one there.
    fn with_principal<T>(&self, board_reference: &str, principal: u64, f: impl FnOnce(&mut PrincipalHold) -> T) -> Option<T> {
        self.lock(board_reference).principals.get_mut(&principal).map(f)
    }

    /// Returns the line of ordinal `k` in the principal's queue, where one
    /// stands.
    fn line_of(&self, board_reference: &str, principal: u64, k: u64) -> Option<HeldLine> {
        self.with_principal(board_reference, principal, |ph| ph.queue.line(k)).flatten()
    }

    /// Returns how many lines stand on `doc` in the principal's queue.
    fn count_of(&self, board_reference: &str, principal: u64, doc: &str) -> u64 {
        self.with_principal(board_reference, principal, |ph| ph.count(doc)).unwrap_or(0)
    }

    /// Returns what a `held` event says of the principal's lines on `doc`.
    fn lines_on(&self, board_reference: &str, principal: u64, doc: &str) -> LinesOn {
        self.with_principal(board_reference, principal, |ph| ph.lines_on(doc)).unwrap_or_default()
    }

    /// Returns how many lines of the session's principal stand held on `doc`.
    ///
    /// They count at its board, in any state (§3c.4, THE HELD-LINES GATE).
    /// It is the shell's one write door's fourth question
    /// (`Shell::write_door`), asked of a whole-draft write — the restore's,
    /// the merge rows' and the shot's — for each draft it writes: a count
    /// above zero refuses the write `held_lines`, since landing it would put
    /// the draft under words the person typed and the board has not kept.
    /// Every standing line counts, whatever its state — holding, sending,
    /// refused, moved, `head_unreadable`, `session_died` — read under the
    /// board's lock off the principal's queue's entry for `doc`
    /// (`HeldQueue::count_on`), whose file its session's open read whole
    /// (§3c.7), and walking no line; nothing is opened, dialed or moved here.
    ///
    /// # Panics
    ///
    /// Panics where the session's board is none the holds were opened over
    /// (the type's precondition).
    pub fn held_lines(&self, session: &SessionEntry, doc: &str) -> u64 {
        self.count_of(&session.board_reference, session.facts.principal, doc)
    }

    /// Sets the own node's stopped state as its owner reports it (§3c.4).
    ///
    /// While it stands, every burst holds `stopped`, and the probe waits for
    /// `Running` to resend. Each edge's `daemon` event is its caller's to say
    /// (`Shell::set_node_state`), so it is marked told here: the feed thread
    /// says neither again, and a state left told before the stop owes nothing
    /// after the start (§4b.2; skep #865).
    pub fn set_node_stopped(&self, board_reference: &str, stopped: bool) {
        let mut board_hold = self.lock(board_reference);
        board_hold.node_stopped = stopped;
        board_hold.told = if stopped { BoardState::Stopped } else { BoardState::Running };
    }

    /// Returns whether the board's node stands stopped by its owner's act.
    ///
    /// The act is [`Holds::set_node_stopped`]'s, and `probe` dials nothing
    /// while it stands. A board that is not the own node answers false.
    pub fn node_stopped(&self, board_reference: &str) -> bool {
        self.lock(board_reference).node_stopped
    }

    /// Returns whether another shell holds the board's held store (§3c.3).
    ///
    /// While it does, this shell reads alone at the board: the shell's one
    /// write door (`Shell::write_door`) refuses every write there
    /// `another_window` before any dial — the `op` row's, the publication
    /// and merge families', the restore's and the ceremonies' (skep #829) —
    /// so no line is held and nothing sent ([`Directory::AnotherWindow`]).
    /// The state is found as the store's touch ([`Holds::touch_store`]: a
    /// session's open, a ceremony's door; skep #880) or a probe tries the
    /// board's locks — another shell holding the board's own directory's
    /// lock, or the pending one's: one writer per board (skep #828) — and
    /// left once this shell locks the board's own directory, or, while the
    /// head will not read, the pending one, each edge emitted as
    /// `another-window` ([`Holds::step`]; skep #827). It reads the state as
    /// it stands, and tries nothing.
    pub fn another_window(&self, board_reference: &str) -> bool {
        matches!(self.lock(board_reference).directory, Directory::AnotherWindow { .. })
    }

    /// Returns the held file P38 halted for `principal` at the board.
    ///
    /// It is the native side's read, for the embedding app to show the file
    /// (§3c.3): `store_halted` carries the halt's `why` alone, and no path
    /// crosses the bridge (§4b.3; SP-15). It answers the file wherever the
    /// principal's door answers `store_halted` — the custody stands for the
    /// shell's life — and `None` otherwise: no file halted, or none read
    /// yet, since nothing is opened here (P39).
    pub fn halted_file(&self, board_reference: &str, principal: u64) -> Option<PathBuf> {
        self.lock(board_reference).halted(principal).map(|(path, _)| path.to_path_buf())
    }

    /// Returns what `principal`'s held file at the board still owes (§3c.3).
    ///
    /// It is the native side's read of what a close leaves behind
    /// (`CopiesOwed`; skep #860), keyed as [`Holds::halted_file`] is, so a
    /// reader with no session standing asks it too. It reads the principal's
    /// queue as it stands, zero where the shell holds none there: nothing is
    /// opened here (P39), and no count of it crosses the bridge.
    pub fn copies_owed(&self, board_reference: &str, principal: u64) -> CopiesOwed {
        self.with_principal(board_reference, principal, |ph| ph.queue.copies_owed()).unwrap_or_default()
    }

    /// Touches the board's held store where it is not yet whole (§3c.1,
    /// §3c.3; skep #828, #880).
    ///
    /// The store is not yet whole while the board's own directory is not
    /// this shell's — by a device's refusal, another shell's lock, or no term
    /// read yet. There, the board's head is read once, outside the lock, and
    /// the store established from it ([`Holds::establish`]): the pending lock
    /// tried first, then the board's own where a term reads, every lock taken
    /// kept for the shell's life, and a lock found held making the store
    /// another shell's ([`Directory::AnotherWindow`]). At a store already
    /// whole nothing is read and nothing tried. It is the board's half of a
    /// session's open ([`Holds::open_session`]) and the touch the shell's one
    /// write door takes before it answers a ceremony, which runs under no
    /// session of this shell's (`Shell::write_door`), so a shell that has
    /// opened no session at the board answers [`Holds::another_window`] from
    /// the board's locks as they stand.
    ///
    /// # Panics
    ///
    /// Panics where `board_reference` names no board the holds were opened
    /// over (the type's precondition).
    pub fn touch_store(&self, board_reference: &str) {
        let slot = self.slot(board_reference);
        // The head is read outside the lock, once, where the store is not yet
        // whole (the board keeps a term once read).
        if slot.lock().directory.tries() {
            let head = board_head(&slot.board);
            self.note_head(board_reference, &head);
            self.establish(board_reference, slot, &head);
        }
    }

    /// Takes a session opened at the board (§3c.7 items 1 and 4).
    ///
    /// The board's store is touched where it is not yet whole
    /// ([`Holds::touch_store`]); and the session's principal's file is read
    /// under its account by the principal's door — P38's faces kept, a
    /// misplaced file set aside and said in the shell's own window — so
    /// `held(session)` lists its lines at once, a bare session's among them,
    /// and the next probe resends them where a session of the principal's
    /// may write. No other principal's file is opened (P39), and none at all
    /// where another shell holds the board's store.
    pub fn open_session(&self, session: &SessionEntry) {
        self.touch_store(&session.board_reference);
        // A halted file is answered at the principal's next act.
        let _ = self.principal_hold(&mut self.lock(&session.board_reference), session);
    }

    /// Establishes the board's store where it is not yet whole, from one
    /// read of the board's head.
    ///
    /// `head` is the board's head as the caller read it (`sessions::board_head`)
    /// — the store's touch reads it once where the store is not yet whole
    /// ([`Holds::touch_store`]: a session's open, a ceremony's door), and the
    /// probe once per probe (`resend`'s `drain`), the one answer deciding the
    /// store here and the documents the resend skips, so no probe reads the
    /// head twice for the hold's sake. A term names the
    /// board's chain, remembered for every later try ([`BoardHold::chain`]):
    /// the board's own directory is made and locked from here on, at this
    /// try or a later one. Then the locks this shell does not hold are tried
    /// ([`Holds::step`]) and every principal's queue brought to the store as
    /// it stands ([`Holds::settle_queues`]). The store is made and locked
    /// under the board's lock, as the files are read under it. A hold never
    /// comes here: it never dials to learn where to write.
    fn establish(&self, board_reference: &str, slot: &BoardSlot, head: &HeadRead) {
        let mut board_hold = slot.lock();
        if let Ok(Some(term)) = head {
            board_hold.chain = Some(Chain::from_bytes(term.chain));
        }
        self.step(board_reference, &mut board_hold, slot.board.dialed());
        self.settle_queues(&mut board_hold);
    }

    /// Tries the board's locks this shell does not hold, and says each edge
    /// of the store's standing once (§3c.1, §3c.3; skep #828, #873).
    ///
    /// It is the store's one step ([`Directory::step`]), taken at the store's
    /// touch — a session's open, a ceremony's door — and at a probe, from the
    /// head read each makes ([`Holds::establish`]); at every probe while the
    /// store is not yet whole ([`Holds::retry_store`]); and at every copy
    /// while the device refuses it ([`Holds::principal_hold`]). Nothing is
    /// tried once both locks are this shell's. The edges (SP-11): as the
    /// store becomes another shell's, what this shell does meanwhile and the
    /// lines held before it — those on the pending file, and those in
    /// memory, which a close before they are sent loses — said once on
    /// `Talk` and emitted once as `another-window`, `true`
    /// ([`Holds::emit_another_window`]; skep #827); as this shell takes the
    /// store from that state, the pending one or the board's own, said once
    /// and emitted once, `false`; a try that finds no change says and emits
    /// nothing. The device's refusal of the store — the pending directory or
    /// its lock, or the board's own — is said once per change of its cause,
    /// and the store taken after one said once ([`Holds::say_store`]).
    fn step(&self, board_reference: &str, board_hold: &mut BoardHold, origin: &Origin) {
        if !board_hold.directory.tries() {
            return;
        }
        let was_another = matches!(board_hold.directory, Directory::AnotherWindow { .. });
        let current = std::mem::replace(&mut board_hold.directory, Directory::NotYet(io::Error::other("the store is being tried")));
        let Stepped { next, chain_refused } = current.step(&self.data_dir, origin, board_hold.chain);
        board_hold.directory = next;
        match &board_hold.directory {
            Directory::AnotherWindow { .. } if !was_another => {
                self.say_another_window(board_hold);
                self.emit_another_window(board_reference, true);
            }
            Directory::ThisWindow { chain, .. } if was_another => {
                let store = if chain.is_some() { "held store" } else { "pending held store" };
                self.say(format_args!("this shell holds this board's {store} now: writes at the board go out again"));
                self.emit_another_window(board_reference, false);
            }
            _ => {}
        }
        match (&board_hold.directory, chain_refused) {
            (Directory::NotYet(refused), _) => {
                let cause = format!("{refused}; the lines held meanwhile wait in memory, written as soon as it can be, tried again at each copy and each probe, and a close before then loses them");
                self.say_store(board_hold, cause);
            }
            (Directory::ThisWindow { .. }, Some(refused)) => {
                let cause = format!("{refused}; the lines held meanwhile stay on the pending held file, tried again at each probe and each session's open");
                self.say_store(board_hold, cause);
            }
            (Directory::ThisWindow { .. }, None) if board_hold.store_said.take().is_some() => self.say("the board's held store is made and locked: the lines held meanwhile go to it"),
            _ => {}
        }
    }

    /// Says why the store could not be taken, once per change of the cause
    /// (SP-11, SP-12): `cause` is said where it is not the one standing
    /// ([`BoardHold::store_said`]).
    fn say_store(&self, board_hold: &mut BoardHold, cause: String) {
        if board_hold.store_said.as_deref() != Some(cause.as_str()) {
            self.say(&cause);
            board_hold.store_said = Some(cause);
        }
    }

    /// Runs the store's retry at a probe (§3c.3; skep #857, #859, #873).
    ///
    /// It is the one act that moves the board's store and its queues on,
    /// under the board's lock at every probe whatever the board's state —
    /// it dials nothing, so space freed, or a lock let go, while no one types
    /// is enough: the locks this shell does not hold are tried again
    /// ([`Holds::step`]); every principal's queue is brought to the store as
    /// it stands ([`Holds::settle_queues`]) — its file read where it is not
    /// yet, the pending → chain change made where the board's own directory
    /// is this shell's now; and each queue's retry writes the copies its file
    /// owes (`HeldQueue::retry`), the wait said at its edges
    /// ([`Holds::note_waiting`]), and each document whose lines those copies
    /// have written is told so under `sessions`, the board's own
    /// ([`Holds::say_landed`]). A term the head has not named is learned at
    /// a probe's or an open's head read alone ([`Holds::establish`]). It
    /// answers the moved faces those landings owe their hands, each beside
    /// the session it is owed to, for the probe to say once the board's lock
    /// is let go ([`Holds::say_with_hands`]; skep #972).
    #[must_use = "a landing's owed `held` event is said by `Holds::say_with_hands` once the board's lock is let go"]
    fn retry_store(&self, board_reference: &str, board_hold: &mut BoardHold, origin: &Origin, sessions: &[Arc<SessionEntry>]) -> Vec<(Arc<SessionEntry>, HandsOwed)> {
        self.step(board_reference, board_hold, origin);
        self.settle_queues(board_hold);
        let mut owed = Vec::new();
        for (principal, ph) in &mut board_hold.principals {
            ph.queue.retry();
            self.note_waiting(*principal, ph);
            owed.extend(self.say_landed(*principal, ph, sessions));
        }
        owed
    }

    /// Says each document whose lines the retry has written (§3c.3; skep #860).
    ///
    /// A document a line of which was answered `unwritable`
    /// (`PrincipalHold::unwritable_docs`) and none of whose lines now waits
    /// for a first copy has its `held` event said again under each of
    /// `sessions` of `principal`'s, without the two members, so the face the
    /// page drew from that answer lifts. The event repeats what it last told
    /// the session — its state, its cause, its hands, whether they are named
    /// `again` (skep #989), and its `sendable`, so a document mid-resend stays
    /// `sending` and a moved one keeps the hands read for the verdict it
    /// carries now — beside today's count. Where it told the session nothing,
    /// no line stands, the face it told is a `moved` one for another verdict
    /// than the document stands on now, or the document's first line awaits
    /// the person's act and the face told another state — the walk, under
    /// another session, having refused or moved it since — the queue gives
    /// the state ([`state_on`]) and the head's cause, so that line's state
    /// stays in front (skep #974); a session told nothing of a document no
    /// line stands on hears nothing. A session told no `moved` face for the
    /// verdict a document stands moved on hears nothing here either, whatever
    /// it was told: its event is owed and answered, said with the hands read
    /// once the board's lock is let go ([`HandsOwed`]; skep #972, #973). The
    /// landing's copy may have been made by any act, so the event follows it
    /// within one [`PROBE_CADENCE`].
    #[must_use = "a landing's owed `held` event is said by `Holds::say_with_hands` once the board's lock is let go"]
    fn say_landed(&self, principal: u64, ph: &mut PrincipalHold, sessions: &[Arc<SessionEntry>]) -> Vec<(Arc<SessionEntry>, HandsOwed)> {
        let mut owed = Vec::new();
        let landed: Vec<String> = ph.unwritable_docs.iter().filter(|doc| !ph.queue.waits_on(doc)).cloned().collect();
        for doc in landed {
            ph.unwritable_docs.remove(&doc);
            let lines = ph.lines_on(&doc);
            let judged = ph.judged_on(&doc);
            // The state a first line that awaits the person's act keeps in
            // front, which a face told of another state is not repeated over.
            let standing = ph.first_awaiting_act(&doc).map(|_| state_on(ph, &doc));
            for session in sessions.iter().filter(|session| session.facts.principal == principal) {
                let told = self.told(session, &doc);
                if told.is_none() && lines.held == 0 {
                    continue;
                }
                if let Some((k, reason)) = self.hands_owed_to(session, ph, &doc) {
                    owed.push((Arc::clone(session), HandsOwed { doc: doc.clone(), k, reason, landed: None }));
                    continue;
                }
                let repeats = told.filter(|told| lines.held > 0 && standing.is_none_or(|state| told.state == state) && (told.state != HeldState::Moved || told.moved_for(judged.as_ref())));
                let said = match repeats {
                    Some(told) => HeldSaid { held: lines.held, unwritable: lines.unwritable.clone(), ..told },
                    None => {
                        let state = state_on(ph, &doc);
                        let cause = ph.queue.reasons_on(&doc).next().map(|(_, reason)| reason.cause.clone()).filter(|_| state != HeldState::Moved);
                        let sendable = if state == HeldState::Moved && session.may_write() { ph.sendable_told(&doc) } else { None };
                        let face = MovedFace { sendable, judged: judged.as_ref().filter(|_| state == HeldState::Moved), ..MovedFace::default() };
                        HeldSaid::of(lines.clone(), state, cause.as_deref(), face)
                    }
                };
                self.emit_said(session, &doc, said, None);
            }
        }
        owed
    }

    /// Brings every principal's queue the door has touched to the store as
    /// it stands ([`Holds::settle_queue`]).
    fn settle_queues(&self, board_hold: &mut BoardHold) {
        let touched: Vec<u64> = board_hold.principals.iter().filter(|(_, ph)| ph.touched).map(|(principal, _)| *principal).collect();
        for principal in touched {
            self.settle_queue(board_hold, principal);
        }
    }

    /// Brings one principal's queue to the store as it stands (§3c.1, §3c.3).
    ///
    /// Nothing moves where the store is not this shell's
    /// ([`Directory::NotYet`], [`Directory::AnotherWindow`]) or the principal
    /// is halted. Where it is: a queue whose file is not yet read opens it
    /// ([`Holds::open_queue`]) — the board's own file where the board's own
    /// directory is this shell's, an earlier run's pending file read beside
    /// it, else the pending file; a queue on the pending file opens the
    /// board's own once that directory is this shell's — THE PENDING → CHAIN
    /// CHANGE (skep #859), every line of this run's a copy owed the board's
    /// file from then, written by the retry, the pending file removed once
    /// none is owed; a queue on the board's file is where it stays.
    fn settle_queue(&self, board_hold: &mut BoardHold, principal: u64) {
        let BoardHold { directory, principals, kept_said, .. } = board_hold;
        let Some(ph) = principals.get_mut(&principal) else { return };
        let Directory::ThisWindow { pending, chain } = directory else {
            // The device's refusal of the store is what every line held
            // meanwhile answers; another shell's store refuses the line at
            // the door instead, and the lines held before carry their own.
            if let Directory::NotYet(refused) = directory {
                if !ph.queue.is_opened() {
                    ph.queue.refuse(io::Error::new(refused.kind(), refused.to_string()));
                }
            }
            return;
        };
        let opens = match &ph.custody {
            Custody::Halted { .. } => false,
            Custody::Unopened => true,
            Custody::File => chain.is_some() && ph.queue.is_pending(),
        };
        if !opens {
            return;
        }
        let target = chain.as_ref().map_or(&pending.dir, |chain| &chain.dir);
        // An earlier run's pending file is read beside the board's own file
        // where the queue is not the pending file's own.
        let earlier = (chain.is_some() && !(ph.queue.is_opened() && ph.queue.is_pending())).then_some(&pending.dir);
        self.open_queue(ph, principal, target, earlier, kept_said);
    }

    /// Opens `principal`'s file in `dir` and takes it as the queue's: the
    /// door's open, and the pending → chain change (§3c.1, §3c.3; skep #857,
    /// #858, #859, #875).
    ///
    /// `dir` is the file's directory, the board's own or the pending one,
    /// and `earlier` the pending directory where an earlier run's pending
    /// file is read beside the board's own file at the first touch. In this
    /// order, each step's refusal leaving the queue as it stood for the next
    /// retry ([`Holds::keep_from_file`]): (1) the file is read, P38's faces
    /// kept — a halted file halts the principal ([`Holds::halt`]), the
    /// pending file left as it stands where the board's file is halted at
    /// the change (skep #858); a misplaced file set aside and said; (2) a
    /// file holding a line under an ordinal below the counter — read after
    /// the first touch — has its standing lines renumbered past it first,
    /// one copy ([`PrincipalHold::renumbers`]; skep #875); (3) `earlier`'s
    /// file is read — a halted one halting the principal before any hold
    /// (skep #857) — and its standing lines enter under fresh ordinals, each
    /// owed its copy, one a standing line already carries passed over
    /// (`Joining::EarlierRun`); (4) the hold takes the file, this run's lines
    /// entering under their own ordinals, owed ([`PrincipalHold::take`]), and
    /// the retry writes every copy owed as one copy, one by one where the
    /// device refuses it; the pending file the lines came from — `earlier`'s,
    /// or the queue's own at the change — is removed once none is owed
    /// (`HeldQueue::supersede`). A file that opens after its read was refused
    /// says so, and one `Talk` line names the lines that moved and those
    /// renumbered; the crash's tail an open found is said once (P39).
    fn open_queue(&self, ph: &mut PrincipalHold, principal: u64, dir: &HeldDir, earlier: Option<&HeldDir>, kept_said: &mut HashMap<u64, String>) {
        let account = ph.account.clone();
        // (1) The file, read.
        let mut file = match dir.open_file(principal, &account) {
            Ok(Opened::Live { queue, aside }) => {
                self.note_aside(principal, aside.as_deref());
                queue
            }
            Ok(Opened::Halted { path, why }) => return self.halt(ph, principal, path, why),
            Err(e) => return self.keep_from_file(ph, principal, kept_said, unread_cause(principal, dir, &e), store_refused("the held file could not be read", &e)),
        };
        // (2) Its lines below the counter, renumbered past it.
        let renumbered = if ph.renumbers(&file) {
            match file.renumber(&mut ph.next_k) {
                Ok(moved) => moved.len(),
                Err(refused) => {
                    let cause = unrenumbered_cause(principal, dir, &refused);
                    return self.keep_from_file(ph, principal, kept_said, cause, refused.error);
                }
            }
        } else {
            0
        };
        // The greatest is within `MAX_ORDINAL`, so its successor is a `u64`.
        ph.next_k = ph.next_k.max(file.greatest_k() + 1);
        // (3) An earlier run's pending file, its lines under fresh ordinals.
        let mut count = 0;
        let mut superseded = None;
        if let Some(pending) = earlier {
            match pending.open_file(principal, &account) {
                Ok(Opened::Live { queue: earlier_run, aside }) => {
                    self.note_aside(principal, aside.as_deref());
                    self.note_torn(principal, &earlier_run);
                    let joined = file.join(&earlier_run, Joining::EarlierRun { next_k: &mut ph.next_k });
                    count += joined.entered.len();
                    if joined.left == 0 {
                        superseded = Some((earlier_run.path().to_path_buf(), joined.entered.iter().map(|&(_, k)| k).collect(), Vec::new()));
                    }
                }
                Ok(Opened::Halted { path, why }) => return self.halt(ph, principal, path, why),
                Err(e) => return self.keep_from_file(ph, principal, kept_said, unread_cause(principal, pending, &e), store_refused("the pending held file could not be read", &e)),
            }
        }
        // (4) The hold takes the file, this run's lines owed to it; the
        // pending file they stand on is superseded, its lines parked until
        // their copies land.
        self.note_torn(principal, &file);
        let (joined, replaced) = ph.take(file);
        count += joined.entered.len();
        if replaced.is_opened() && replaced.is_pending() {
            superseded = Some((replaced.path().to_path_buf(), replaced.standing_on_disk(), replaced.dones_owed()));
        }
        if let Some((path, standing, left)) = superseded {
            ph.queue.supersede(path, standing, left);
        }
        if kept_said.remove(&principal).is_some() {
            self.say(format_args!("principal {principal}'s {} opens: the lines held for the principal go to it", file_word(dir)));
        }
        if count > 0 {
            let plural = if count == 1 { "" } else { "s" };
            let past = match renumbered {
                0 => String::new(),
                1 => "; the 1 line an earlier run left in it is renumbered past this run's ordinals, and sent after this run's lines".to_string(),
                n => format!("; the {n} lines an earlier run left in it are renumbered past this run's ordinals, and sent after this run's lines"),
            };
            self.say(format_args!("principal {principal}: {count} held line{plural} joined {}{past}", the_file(dir)));
        }
        self.note_waiting(principal, ph);
    }

    /// Halts `principal` at the board: P38's halt, found at the first touch
    /// or at the pending → chain change (§3c.3; skep #857, #858).
    ///
    /// Every act is answered `store_halted` from here
    /// ([`Holds::principal_hold`]), no line of the principal's is sent
    /// (`PrincipalHold::drains`), the lines standing — on the pending file at
    /// the change, or in memory where the device refused the store before —
    /// left as they stand, and the halt is said once in the shell's own
    /// window ([`halted_line`]), the file shown again at each `held.show`.
    fn halt(&self, ph: &mut PrincipalHold, principal: u64, path: PathBuf, why: HaltWhy) {
        self.say(halted_line(principal, &path, why));
        ph.custody = Custody::Halted { path, why };
    }

    /// Keeps `principal`'s lines from its file: the file's read, or the
    /// renumbering copy it owed, refused by the device (§3c.3).
    ///
    /// The queue stands as it did for the next retry
    /// ([`Holds::retry_store`]) — its file not yet read, every line held
    /// meanwhile owed under `refused` (`HeldQueue::refuse`), or on the
    /// pending file at the change — and `cause` is said once per change
    /// ([`Holds::say_kept_from_file`]) with where the lines stand.
    fn keep_from_file(&self, ph: &mut PrincipalHold, principal: u64, kept_said: &mut HashMap<u64, String>, cause: String, refused: io::Error) {
        let left = if ph.queue.is_opened() {
            "the lines held for the principal stay on the pending held file meanwhile, tried again at each probe and each session's open"
        } else {
            "the lines held for the principal wait in memory until it reads, tried again at each copy and each probe, and a close before then loses them"
        };
        self.say_kept_from_file(kept_said, principal, cause, Some(left));
        if !ph.queue.is_opened() {
            ph.queue.refuse(refused);
        }
        self.note_waiting(principal, ph);
    }

    /// Says, once as it begins, that another shell holds the board's store.
    ///
    /// It is the edge [`Holds::step`] says (§3c.3; SP-11): this shell reads
    /// alone at the board, every write refused `another_window` before any
    /// dial and nothing held, the store tried again at each probe and each
    /// session's open; and the lines `board_hold` holds from before the state
    /// was found, all sent as the board takes them, each count apart: those
    /// on the pending file, which stay there under this shell's lock, and
    /// those in memory alone, which a close before then loses (SP-12). No
    /// path is said (SP-15).
    fn say_another_window(&self, board_hold: &BoardHold) {
        let (mut on_file, mut in_memory) = (0usize, 0usize);
        for ph in board_hold.principals.values() {
            let standing = ph.queue.len();
            if ph.queue.is_opened() {
                on_file += standing;
            } else {
                in_memory += standing;
            }
        }
        let on_file = match on_file {
            0 => String::new(),
            1 => "; the 1 held line in the pending held file stays there and is sent as the board takes it".to_string(),
            n => format!("; the {n} held lines in the pending held file stay there and are sent as the board takes them"),
        };
        let in_memory = match in_memory {
            0 => String::new(),
            1 => "; the 1 held line kept in memory before then is sent as the board takes it, and a close before then loses it".to_string(),
            n => format!("; the {n} held lines kept in memory before then are sent as the board takes them, and a close before then loses them"),
        };
        self.say(format_args!(
            "another shell holds this board's held store — one shell per data directory: this shell reads alone at the board, every write refused `another_window` before any dial and nothing held, and tries the store again at each probe and each session's open{on_file}{in_memory}"
        ));
    }

    /// Emits `another-window`: another shell's hold on the board's store.
    ///
    /// `another_window` is whether another shell holds the board's held store
    /// at an edge of that state (§3c.3; skep #827): the edge
    /// [`Holds::establish`] says, emitted beside its `Talk` line under the
    /// board's lock, as a hold's `held` event is — the bus takes its own
    /// locks alone, and the shell's watcher reacts to `session-died` alone,
    /// so the emit waits on no board.
    fn emit_another_window(&self, board_reference: &str, another_window: bool) {
        self.bus.emit(EventName::AnotherWindow, json!({"board": board_reference, "another_window": another_window}));
    }

    /// Says why a principal's lines are kept from its file, once per change
    /// of the cause (SP-11, SP-12).
    ///
    /// `cause` is the refusal — the file's read, or the renumbering copy it
    /// owed — and `left` where the lines stand and when they are tried
    /// again. It is said where `cause` is not the one `said` holds for the
    /// principal ([`BoardHold::kept_said`]), and never again while it stands.
    fn say_kept_from_file(&self, said: &mut HashMap<u64, String>, principal: u64, cause: String, left: Option<&str>) {
        if said.get(&principal) == Some(&cause) {
            return;
        }
        match left {
            Some(left) => self.say(format_args!("{cause}; {left}")),
            None => self.say(&cause),
        }
        said.insert(principal, cause);
    }

    /// Says a misplaced file the open set aside, at `aside`, in the shell's
    /// own window (P39): said as the open moves it, so once.
    fn note_aside(&self, principal: u64, aside: Option<&Path>) {
        if let Some(aside) = aside {
            self.say(format_args!("principal {principal}'s held file named another board or principal, and is set aside at {}", aside.display()));
        }
    }

    /// Says the crash's tail the open of `queue`'s file found (P39).
    ///
    /// It is said in the shell's own window once the file's queue is taken
    /// ([`Holds::open_queue`]) — an open whose renumbering is refused reads
    /// the file again at the next retry, and says nothing of it until then.
    fn note_torn(&self, principal: u64, queue: &HeldQueue) {
        match queue.torn() {
            Some(Torn::Header { bytes }) => self.say(format_args!(
                "principal {principal}'s held file holds no whole header line ({bytes} bytes of a torn one — a crash before its header's sync) and is read as fresh; the next line written cuts it and heads the file"
            )),
            Some(Torn::Line { bytes }) => self.say(format_args!(
                "principal {principal}'s held file ends in a torn line of {bytes} bytes — a crash's, held by no one — which the next line written cuts off"
            )),
            None => {}
        }
    }

    /// Notes the board's head as a read of it answered, saying each change
    /// of its state once (skep #727, #865; SP-11).
    ///
    /// Every read of the head feeds it: the probe's ([`Holds::probe`]), the
    /// store's touch ([`Holds::touch_store`]) and each signed write's signing
    /// term ([`Holds::signing_term`]). The state is
    /// `head_unreadable` — the record standing and not reading, served
    /// garbled, or owed by a claimed board and not served — or the head
    /// reading, an unclaimed board that owes none among them; a board away
    /// says nothing of its head and moves it not. One `Talk` line as the head
    /// becomes unreadable, with its cause, and one as it reads again; nothing
    /// per probe, and nothing on a healthy board. It decides the board's
    /// state, and the board's feed thread tells it within one
    /// [`PROBE_CADENCE`] ([`Holds::state_change`]).
    pub(crate) fn note_head(&self, board_reference: &str, head: &HeadRead) {
        let now = match head {
            Ok(_) => HeadState::Reads,
            Err(Refusal::Halt { name: Name::HEAD_UNREADABLE, face }) => HeadState::Unreadable(face.cause.clone()),
            Err(_) => return,
        };
        let was = std::mem::replace(&mut self.lock(board_reference).head, now.clone());
        match (was, now) {
            (HeadState::Unreadable(_), HeadState::Reads) => self.say("the board's head record (`H.1`) reads again; the lines held on it are sent"),
            (HeadState::Unknown | HeadState::Reads, HeadState::Unreadable(cause)) => self.say(format_args!(
                "the board's head record (`H.1`) cannot be read ({cause}); a signed burst is held in the pending held store and skipped at each probe until it reads — the record is the board's own, its operator's to repair"
            )),
            (HeadState::Unknown | HeadState::Reads, HeadState::Reads) | (HeadState::Unreadable(_), HeadState::Unreadable(_)) | (_, HeadState::Unknown) => {}
        }
    }

    /// Returns the principal's hold at `board_hold`'s board.
    ///
    /// It is the principal's door, the one every entry that names a principal
    /// takes: a session's open, a burst, a hold, `held` and `resolve`. The
    /// store's retry runs first where the device refused the store
    /// ([`Directory::NotYet`]; [`Holds::step`]) — before every copy, as the
    /// retry's rule has it — and the principal's queue is brought to the
    /// store as it stands ([`Holds::settle_queue`]): its file read under
    /// `session`'s account where it is not yet — the board's own file where
    /// the board's own directory is this shell's, else the pending one —
    /// P38's faces kept, a misplaced file set aside and said; no file is
    /// read where the store is not this shell's, the queue holding its lines
    /// in memory meanwhile. Under the session that stands, so the restart
    /// arm's re-open is covered too.
    ///
    /// **The first touch** starts the principal's ordinal space
    /// ([`PrincipalHold::next_k`]): the counter is set past the greatest
    /// ordinal in every file the principal's lines can be in that the shell
    /// can name now — the file read above, where one was, and an earlier
    /// run's pending file joined beside it; and, where the queue's file is
    /// not the board's own, the files not read: the origin-named pending
    /// file, where its directory stands and the queue is not on it, and the
    /// board's own file, where its head has named a chain
    /// ([`BoardHold::chain`]) — each of the latter read for its greatest
    /// ordinal alone, nothing written or moved (`HeldDir::greatest_ordinal`);
    /// a read that fails counts nothing, the file's open saying why where it
    /// meets it.
    ///
    /// # Errors
    ///
    /// Returns `store_halted` where P38 halted the principal's file (§3c.3):
    /// every act's refusal, answered at the principal's door, so no act
    /// reaches a halted principal's queue.
    fn principal_hold<'b>(&self, board_hold: &'b mut BoardHold, session: &SessionEntry) -> Result<&'b mut PrincipalHold, Refusal> {
        let principal = session.facts.principal;
        let account = session.facts.account.as_deref().unwrap_or("");
        let origin = session.board.dialed();
        // The store's retry before every copy: a store the device refused is
        // tried again; another shell's is tried at the probes and the touches.
        if matches!(board_hold.directory, Directory::NotYet(_)) {
            self.step(&session.board_reference, board_hold, origin);
        }
        if !board_hold.principals.contains_key(&principal) {
            board_hold.principals.insert(principal, PrincipalHold::new(account, &HeldDir::pending(&self.data_dir, origin), principal));
        }
        self.settle_queue(board_hold, principal);
        let chain = board_hold.chain;
        let ph = board_hold.principals.get_mut(&principal).expect("the principal's hold, entered above");
        if !ph.touched {
            // The first touch: the counter past every file the shell can
            // name now and did not read, the queue's own counted as it was
            // taken.
            ph.touched = true;
            let on_chain = ph.queue.is_opened() && !ph.queue.is_pending();
            if !on_chain {
                let pending = Some(HeldDir::pending(&self.data_dir, origin)).filter(|dir| dir.exists() && !ph.queue.is_opened());
                let board = chain.map(|chain| HeldDir::new(&self.data_dir, chain));
                for file in [pending, board].into_iter().flatten() {
                    if let Ok(greatest) = file.greatest_ordinal(principal) {
                        // The greatest is within `MAX_ORDINAL`, so its
                        // successor is a `u64`.
                        ph.next_k = ph.next_k.max(greatest + 1);
                    }
                }
            }
        }
        if let Custody::Halted { why, .. } = &ph.custody {
            return Err(store_halted(*why));
        }
        Ok(ph)
    }

    /// Sends one frame under `session`: the `op` row's session form.
    ///
    /// An `/op-at` frame aside, the frame goes to the board the session
    /// stands at. A burst ([`is_burst`]) enters by the burst's door and may be
    /// held (`send_burst`), `anchors` — the page's, read at the row's door —
    /// riding its line for the shift (skep #442) and read by no other frame;
    /// one of the unholdable writes
    /// ([`UNHOLDABLE_WRITES`]) meeting a hold that stands at the board is
    /// refused at once with the hold's cause, never dialed
    /// ([`Holds::unholdable_refusal`]) — the shell's write door asked it
    /// before any read, and this is the door's own check behind the shell's,
    /// for a follower write sent at its burst's ack and for a hold that came
    /// to stand since; any other frame — a write the hold
    /// never holds, or a read — is attested where an attest is owed, dialed
    /// and reissued within the call, its ack noted for the base, and every
    /// other answer faced as the refusal it is: a refused run, a lost
    /// answer, a second `write_busy` and a third `durability` among them
    /// (§3c.4: "a non-burst write that fails … is faced at its act"), save
    /// the death signal, answered [`AtDeath::NotABurst`] for the caller to
    /// end the session. A write comes here through the shell's one write
    /// door (`Shell::write_door`): under a session that may write alone
    /// (`SessionEntry::may_write`), at a board whose held store no other
    /// shell holds as it meets the door ([`Holds::another_window`]) — the
    /// `op` row refuses the others before it.
    pub fn send(&self, session: &SessionEntry, frame: Value, anchors: Option<Anchors>) -> OpAnswer {
        if is_burst(&frame) {
            return self.send_burst(session, frame, anchors);
        }
        if let Some(refusal) = self.unholdable_refusal(&session.board_reference, frame["op"].as_str().unwrap_or("")) {
            return OpAnswer::Answered(Err(refusal));
        }
        match self.dial_within_call(session, &frame) {
            Dialed::Acked(ack) => {
                self.note_ack(session, &frame, &ack);
                OpAnswer::Answered(Ok(ack))
            }
            Dialed::Held { refusal, .. } | Dialed::Unanswered { refusal, .. } | Dialed::Reissue { refusal, .. } | Dialed::Faced(refusal) => OpAnswer::Answered(Err(refusal)),
            Dialed::Died => OpAnswer::Died(AtDeath::NotABurst),
        }
    }

    /// Returns the refusal an unholdable write meets at a standing hold (§3c.4).
    ///
    /// `op` is the write's kind. Where it is one of the nine
    /// ([`UNHOLDABLE_WRITES`]) and a hold stands at the board — the own node
    /// stopped, the write path poisoned, the writes halted, in that order —
    /// the write is refused at once under the cause's own name
    /// (`Name::STOPPED`, `Name::POISONED`, `Name::HALTED`), its detail the
    /// `op`, never held and never dialed; `None` where no hold stands or the
    /// kind is not of the nine, the write then dialing as it dials — a board
    /// that is unreachable is no hold of this kind. It is the third question
    /// of the shell's one write door (`Shell::write_door`), asked for every
    /// write the shell sends before any dial and any read the write makes —
    /// a frame through `op` by its op, `publication.confirm` and
    /// `merge.land` with `publish`, `history.restore`, `merge.undo` and
    /// `merge.withdraw` with `set_arrangement`, `merge.compose` with `stage`
    /// where it may stage a fresh draft, else `set_arrangement` — and asked
    /// once more as a frame reaches [`Holds::send`], the door's check behind
    /// the shell's.
    ///
    /// # Panics
    ///
    /// Panics where `board_reference` names no board the holds were opened
    /// over (the type's precondition).
    pub fn unholdable_refusal(&self, board_reference: &str, op: &str) -> Option<Refusal> {
        if !UNHOLDABLE_WRITES.contains(&op) {
            return None;
        }
        let name = match self.lock(board_reference).standing_cause()? {
            cause::STOPPED => Name::STOPPED,
            cause::POISONED => Name::POISONED,
            _ => Name::HALTED,
        };
        Some(Refusal::shell(name, json!({"op": op})))
    }

    /// Sends a burst by the burst's write path (§3c.4).
    ///
    /// Its checks run in this order, the first that holds answering: admitted
    /// by the burst's door ([`Burst::admit`]), its refusal faced at the act;
    /// refused `store_halted` where P38 halted the principal's file (the
    /// principal's door, [`Holds::principal_hold`]); held without a dial where
    /// a hold stands at the board — the own node stopped, else the board silent
    /// (`unreachable`), else the board halted, else a line of the principal's
    /// already held (`behind`), else a request of the hold's at the board
    /// unanswered, its verdict pending (`unreachable`: nothing more is dialed
    /// there until a `/health` answers, §3c.5) — `behind` before the pending
    /// verdict, since until it comes the board may answer still (§4b.2's
    /// `held`: never `unreachable` while the board answers); else dialed within
    /// the call ([`Holds::dial_within_call`]): an ack carried and its `at`
    /// noted; a hold-class answer or a refused run held and answered `held` — a
    /// second `write_busy` and a third `durability` among them (§3c.4's
    /// riders), the line's clock started where the dial was a failed send
    /// ([`held_failure`]); a dial the board gave no answer to held
    /// `unreachable`, its `sent` the dial's, no clock started and the board
    /// marked unanswered ([`Holds::hold_unanswered`]); a burst the board
    /// refuses as typed against an older state of its document shifted through
    /// the change and sent again within the call where it carries anchors
    /// ([`Holds::shift_at_first_dial`]), so the page meets the ack or the next
    /// refusal — else, or where the shift is not exact, held as a moved
    /// document and answered `held`, its line carrying the board's verdict and
    /// the `held` event naming the hands whose rows moved the document — one
    /// more read the call waits on ([`Holds::hands_since_typed_state`]), and
    /// for another device's key the read of its account's labels
    /// ([`Holds::recorded_label`]); the death signal — at the dial, or at
    /// that read of the hands — held `session_died`, `sent: false`, before
    /// the caller ends the session ([`Holds::hold_at_death`]; [`AtDeath`]),
    /// so the line stands through the end's reads with every later burst of
    /// the principal's behind it, its clock started where the dial was a
    /// failed send; anything else faced at the act.
    ///
    /// The `base` a held line takes — the position the resend's read of it
    /// starts from (§3c.2) — is read under the board's lock BEFORE the dial,
    /// with the standing hold, and handed to the hold either path takes
    /// ([`Holds::hold_line`] at once, [`Holds::hold`] or
    /// [`Holds::hold_at_death`] after the dial): an ack of another write of
    /// the principal's read while the dial is out — a sibling session's, or
    /// the person's on another connection — raises the base of the next hold
    /// alone, never this line's, so the read of a line whose answer was lost
    /// starts below its own landing (skep #737).
    ///
    /// **Anchors that name held words** (skep #969). Past the hold's own
    /// door, and before any hold or dial, the pieces the burst's anchors
    /// name are asked of the principal's hold ([`Holds::place_anchors`]):
    /// a piece naming a burst held on the document binds to its line as the
    /// burst's line enters, the burst holding `behind` it — a line of the
    /// principal's stands — and one naming a burst kept there is placed at
    /// its minted address now; a refusal there is faced at the act, nothing
    /// held and nothing dialed.
    ///
    /// **A burst held behind an act owed** (skep #974). Where the burst is
    /// held behind a line of its document that awaits the person's act — a
    /// refused run's, or a moved document's — the `held` event says that
    /// line's state, kept in front, its count counting the burst, while the
    /// `held` answer names the burst's own cause ([`Holds::say_entered`]).
    /// Where the document stands moved and no face told this session the
    /// hands of its verdict, the call waits on one read of them more, made
    /// once the board's lock is let go ([`Holds::hands_since_typed_state`]),
    /// and for another device's key the read of its account's labels; none
    /// is made at a board not answering or an own node stopped (SP-23).
    fn send_burst(&self, session: &SessionEntry, frame: Value, anchors: Option<Anchors>) -> OpAnswer {
        let burst = match Burst::admit(frame, session) {
            Ok(burst) => burst.with_anchors(anchors),
            Err(refusal) => return OpAnswer::Answered(Err(refusal)),
        };
        let (burst, base) = {
            let mut board_hold = self.lock(&session.board_reference);
            // A burst's hold before any dial is the own node stopped, else the
            // board silent, else the writes halted (§3c.4's for a burst; a
            // `poisoned` answer is the dial's own, its line held `sent:
            // true`), else a line of the principal's already held, else a
            // request of the hold's unanswered (skep #863).
            let standing = if board_hold.node_stopped {
                Some(cause::STOPPED)
            } else if board_hold.silent() {
                Some(cause::UNREACHABLE)
            } else if board_hold.writes_halted {
                Some(cause::HALTED)
            } else {
                None
            };
            let pending = board_hold.pending();
            let (line_stands, base) = match self.principal_hold(&mut board_hold, session) {
                Ok(ph) => (!ph.queue.is_empty(), ph.base_of(&burst.doc, session.opened_at)),
                Err(refusal) => return OpAnswer::Answered(Err(refusal)),
            };
            // The hold's own door behind the shell's (§3c.3): a burst that
            // passed the write door before another shell's store was found
            // is refused as the door would have refused it, nothing held.
            if let Some(refusal) = another_window(&board_hold, &burst) {
                return OpAnswer::Answered(Err(refusal));
            }
            // The words the anchors name (skep #969): a burst held on the
            // document, which a line of the principal's standing holds this
            // one behind, or one kept there, which places them now.
            let ph = board_hold.principals.get(&session.facts.principal).expect("the principal's hold, entered by its door");
            let burst = match Holds::place_anchors(ph, burst) {
                Ok(burst) => burst,
                Err(refusal) => return OpAnswer::Answered(Err(refusal)),
            };
            let hold_cause = standing.or(line_stands.then_some(cause::BEHIND)).or(pending.then_some(cause::UNREACHABLE));
            if let Some(cause) = hold_cause {
                return OpAnswer::Answered(self.hold_line(board_hold, session, burst, Reason::of(cause, false), base));
            }
            (burst, base)
        };
        match self.dial_within_call(session, burst.frame()) {
            Dialed::Acked(ack) => {
                self.note_ack(session, burst.frame(), &ack);
                OpAnswer::Answered(Ok(ack))
            }
            // The board's verdict on the typed state, and the burst carries
            // its anchors: the shift, within the call.
            Dialed::Held { reason, refusal } if reason.cause == cause::MOVED && burst.anchors.is_some() => {
                let failed = held_failure(&reason, &refusal);
                self.shift_at_first_dial(session, burst, reason, refusal, failed, base)
            }
            Dialed::Held { reason, refusal } => {
                let failed = held_failure(&reason, &refusal);
                self.hold(session, burst, reason, failed, base)
            }
            Dialed::Unanswered { reason, refusal } => self.hold_unanswered(session, burst, reason, &refusal, base),
            Dialed::Reissue { refusal, .. } | Dialed::Faced(refusal) => OpAnswer::Answered(Err(refusal)),
            // The death is neither (§3c.4): the burst is held before the
            // caller ends the session, a dead token's write having committed
            // nothing and its dial no failed send.
            Dialed::Died => self.hold_at_death(session, burst, None, base),
        }
    }

    /// Places the pieces a burst's anchors name, at the burst's door.
    ///
    /// A piece names `offset` positions into the words of a burst of the
    /// page's on the burst's own document, by the `id` that burst's frame
    /// carried (skep #969). Each edge that is a piece — `before`, then
    /// `after` — is asked of `ph`, the principal's hold at the board: the
    /// newest line standing on the document with that `id`, which the piece
    /// binds to as the burst's line enters (`held`'s anchors that name held
    /// words) and the burst holds behind; else the newest insert of the
    /// principal's kept there with that `id`
    /// ([`PrincipalHold::landed_insert`]), whose minted address places the
    /// piece now ([`Anchors::placed`]). The burst is answered with its
    /// anchors so placed; one with no piece passes as it came.
    ///
    /// # Errors
    ///
    /// Returns, at the first edge whose piece is not of its place, nothing
    /// held and nothing dialed:
    ///
    /// * `malformed_args` naming `anchors.before` or `anchors.after` where
    ///   the burst it names is no insert, where its `offset` is not below the
    ///   positions that insert's values seat (`wire::values_of`), or where
    ///   the address it would place is past what an I-address spells;
    /// * `no_such_burst` `{anchor, burst}` — `anchor` the edge, `burst` the
    ///   `id` — where no burst of that `id` stands held on the document or
    ///   is kept there in the record's memory.
    fn place_anchors(ph: &PrincipalHold, mut burst: Burst) -> Result<Burst, Refusal> {
        let Some(mut anchors) = burst.anchors.take() else { return Ok(burst) };
        let positions = |frame: &Value| (frame["op"] == "insert").then(|| values_of(&frame["values"]).ok()).flatten().map(|values| values.len() as u64);
        for edge in ["before", "after"] {
            let anchor = if edge == "before" { &anchors.before } else { &anchors.after };
            let Some(Anchor::Piece(piece)) = anchor else { continue };
            let (id, offset) = (piece.burst().to_string(), piece.offset());
            let malformed = || Refusal::malformed(format!("anchors.{edge}"));
            if let Some(frame) = ph.queue.frame_named(&burst.doc, &id) {
                if positions(frame).is_none_or(|positions| offset >= positions) {
                    return Err(malformed());
                }
                continue;
            }
            let Some(landed) = ph.landed_insert(&burst.doc, &id) else {
                return Err(Refusal::shell(Name::NO_SUCH_BURST, json!({"anchor": edge, "burst": id})));
            };
            if offset >= landed.positions {
                return Err(malformed());
            }
            anchors = anchors.placed(&id, &landed.addr).ok_or_else(malformed)?;
        }
        burst.anchors = Some(anchors);
        Ok(burst)
    }

    /// Shifts a burst refused stale at its first dial, and resends it.
    ///
    /// The board refused it as typed against an older state of its document,
    /// and it is sent again within the call (skep #442, #751; §4b.1's `op`
    /// row). The burst carries its anchors, and the board's verdict (`reason`)
    /// names the state it was typed against and the document's current one.
    /// The line is entered first — as the verdict held it, `moved` with the
    /// verdict on it, no dial of it having landed — and said to no one yet:
    /// a line awaiting the person's act is one no probe sends, so no second
    /// thread dials it while this one shifts it, and the page meets the ack
    /// or the next refusal within the call, never a `held` event for a line
    /// this call settles. It is taken for the call's dials in the lock that
    /// enters it ([`LineOut`]), so no person's act takes it meanwhile (skep
    /// #983), each shifted dial's answer noted on it, and let go once the
    /// call has settled it, before its face is told. Then the shift and the
    /// shifted dial, made as the
    /// resend makes them ([`Holds::shift_and_send`], the one function) save
    /// that no turn bounds the call's shifts, which spend no step
    /// (`resend::no_step`): the shifted frame written to the line before it
    /// is dialed, the dial reissued within the call as a first dial's is.
    /// Its answer settles the line as the resend's answers settle one: an ack
    /// keeps it, its `at` noted, and is the call's answer — no `held` event,
    /// the line entered and settled within one call; the verdict again shifts
    /// it again, as far as the line's deadline lets it — the line born here
    /// with its clock started by `failed`, the first dial's failed send, the
    /// board's first refusal, and every failed send of a shifted dial noted
    /// on it ([`HAND_OVER_DEADLINE`]); a hold-class answer or a refused run — a
    /// second `write_busy` among them — re-marks it, `sent` kept, and answers
    /// `held` under that cause; an answer a first dial faces drops the line,
    /// entered for the shift alone, and faces it; the death signal — at the
    /// shifted dial, or at the shift's read, which dials nothing — re-marks
    /// it `session_died`, `sent` kept, and says it `holding`, the line
    /// standing for the session that stands next and the caller ending this
    /// one ([`AtDeath::Held`]); a request the board gives no answer to — the
    /// shift's read or its attest's, nothing dialed, or the shifted dial —
    /// re-marks it `unreachable`, `sent` kept, says it `holding` and answers
    /// `held` under that cause, the board marked unanswered and the send owed
    /// to the verdict where its dial left (skep #863): a shift whose read
    /// went unanswered is untried, never a reason it is not exact, and its
    /// verdict is kept (`PrincipalHold::shift_owed`) for the resend to run
    /// it when the board answers. Where a line ahead of this one on its
    /// document awaits the person's act, the face each of those three ends
    /// tells says that line's state instead ([`Holds::say_after_shift`];
    /// skep #974). `refusal` is the board's refusal the verdict rides. Where
    /// the shift is not exact — a delete or a rearrange without its span, an
    /// anchor lost or at two places, the span
    /// between them cut or refilled, the read refused, the deadline passed —
    /// the line is the moved hold as a burst without anchors meets it: the
    /// hands read once ([`Holds::hands_since_typed_state`]) before anything is
    /// marked, then the newest verdict on the line, the `held` event `moved`,
    /// the call answered `held`; a death at that read re-marks the line as
    /// the death at a shifted dial does, and leaves a burst held behind it
    /// unmarked; the board's silence at it, or an answer with no page, names
    /// the hands not read ([`Hand::UNREAD`]), read again as the walk meets the
    /// document (skep #972), and a history the board has reclaimed names them
    /// `unknowable` ([`Hand::UNKNOWABLE`]), read again never (skep #989).
    fn shift_at_first_dial(&self, session: &SessionEntry, burst: Burst, reason: Reason, refusal: Refusal, failed: Option<String>, base: u64) -> OpAnswer {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let doc = burst.doc.clone();
        // The board's newest refusal of the line as typed stale, its verdict
        // the floor the shift is typed against.
        let mut moved = KeptShift { reason: reason.clone(), refusal };
        // The line is taken for the call's dials in the lock that enters it,
        // so no person's act takes it while the call shifts it (skep #983).
        let (entered, mut out) = {
            let mut board_hold = self.lock(board_reference);
            let entered = match self.enter_line(&mut board_hold, session, burst, reason, failed, base) {
                Ok(entered) => entered,
                Err(refusal) => return OpAnswer::Answered(Err(refusal)),
            };
            let ph = board_hold.principals.get_mut(&principal).expect("the principal's hold, entered by its door");
            let out = LineOut::take(self, board_reference, principal, ph, entered.k).expect("the line, entered under this lock");
            (entered, out)
        };
        let (k, mut answer) = (entered.k, entered.answer);
        // Whether a shifted dial left, the mark made before it: the line
        // keeps it through every later answer, as a resend's line does.
        let mut sent = false;
        // The death — at a shifted dial, at the shift's read, or at the moved
        // hold's read of the hands — holds the line as the death at a first
        // dial holds a burst, said now, since the line was said to no one
        // while it was the shift's. Here and at every other end of the call
        // the line is let go before its face is told, so an act the face asks
        // for takes it.
        let at_death = |sent: bool, mut answer: Value, out: LineOut<'_>| {
            self.with_principal(board_reference, principal, |ph| self.remark_line(principal, ph, k, Reason::of(cause::SESSION_DIED, sent)));
            drop(out);
            answer["cause"] = Value::from(cause::SESSION_DIED);
            self.say_after_shift(session, &doc, k, HeldState::Holding, cause::SESSION_DIED);
            OpAnswer::Died(AtDeath::Held(DeathHeld { k, answer }))
        };
        loop {
            let verdict = moved.reason.refusal.clone().unwrap_or(Value::Null);
            let shifted = match self.shift_and_send(session, k, &verdict, Dialing::First, resend::no_step, |frame| self.dial_reissuing(session, frame)) {
                Ok(shifted) => shifted,
                Err(why) => {
                    // The hands are read before anything is marked, so the
                    // death at the read leaves a burst held behind the line
                    // as it stood.
                    let held_moved = Reason { cause: cause::MOVED.to_string(), refusal: Some(verdict.clone()), sent };
                    let Some(HandsFace { hands, again, unanswered }) = self.hands_since_typed_state(session, &doc, Some(k), &held_moved).face() else { return at_death(sent, answer, out) };
                    if hands.contains(&Hand::UNREAD) {
                        self.with_principal(board_reference, principal, |ph| ph.hands_owed.insert(doc.clone(), k));
                    }
                    if unanswered {
                        self.note_unanswered(&mut self.lock(board_reference), None);
                    }
                    self.say(format_args!("line {k} on {doc} was not shifted ({why}); the document is held as moved"));
                    let judged = Judged::of(k, &held_moved);
                    self.mark_moved(board_reference, principal, &doc, Some((k, verdict)));
                    let sendable = self.note_shift_refused(board_reference, principal, &doc, k, &why);
                    drop(out);
                    let face = MovedFace { hands: &hands, again, sendable, judged: judged.as_ref() };
                    self.emit_held(session, &doc, self.lines_on(board_reference, principal, &doc), HeldState::Moved, None, face);
                    return OpAnswer::Answered(Ok(answer));
                }
            };
            sent |= shifted.left;
            if shifted.left {
                out.answered(&shifted.dialed);
            }
            // A shifted dial that failed is a failed send of the line, as at
            // a resend; one whose attest could not be composed left nothing.
            if let Some(token) = shifted.left.then(|| shifted.dialed.failure()).flatten() {
                self.note_failure(board_reference, principal, k, token);
            }
            match shifted.dialed {
                Dialed::Acked(ack) => {
                    self.note_ack(session, &shifted.frame, &ack);
                    let minted = minted_by(&shifted.frame, &ack);
                    self.with_principal(board_reference, principal, |ph| self.keep_line(principal, ph, k, acked_at(&ack), minted));
                    return OpAnswer::Answered(Ok(ack));
                }
                Dialed::Held { reason, refusal } if reason.cause == cause::MOVED => {
                    moved = KeptShift { reason, refusal };
                }
                Dialed::Unanswered { reason, refusal } => {
                    // The line holds `unreachable`, said now since it was said
                    // to no one while it was the shift's; a shift whose read
                    // went unanswered keeps its verdict for the resend.
                    let cut = (shifted.left && reason.sent).then(|| CutSend { principal, k, doc: doc.clone(), at: self.now(), refusal: refusal.to_string() });
                    self.with_principal(board_reference, principal, |ph| {
                        if !shifted.left {
                            ph.shift_owed.insert(k, moved.clone());
                        }
                        self.remark_line(principal, ph, k, Reason::of(cause::UNREACHABLE, sent));
                    });
                    self.note_unanswered(&mut self.lock(board_reference), cut);
                    drop(out);
                    answer["cause"] = Value::from(cause::UNREACHABLE);
                    self.say_after_shift(session, &doc, k, HeldState::Holding, cause::UNREACHABLE);
                    return OpAnswer::Answered(Ok(answer));
                }
                Dialed::Held { reason, .. } => {
                    let state = line_state(&reason);
                    let said = reason.cause.clone();
                    self.with_principal(board_reference, principal, |ph| self.remark_line(principal, ph, k, Reason { sent: reason.sent || sent, ..reason }));
                    drop(out);
                    answer["cause"] = Value::from(said.as_str());
                    self.say_after_shift(session, &doc, k, state, &said);
                    return OpAnswer::Answered(Ok(answer));
                }
                Dialed::Reissue { refusal, .. } | Dialed::Faced(refusal) => {
                    self.with_principal(board_reference, principal, |ph| self.done_line(principal, ph, k, Done::Dropped));
                    return OpAnswer::Answered(Err(refusal));
                }
                Dialed::Died => return at_death(sent, answer, out),
            }
        }
    }

    /// Dials one write within its call (§4b.1's `op` row).
    ///
    /// Reissue-class answers are "reissued by the shell and reach the page as
    /// the ack or the next refusal": `frame` attested once where an attest is
    /// owed ([`Holds::attest_where_owed`]), then dialed and reissued
    /// ([`Holds::dial_reissuing`]), so its caller meets the ack or the next
    /// refusal.
    fn dial_within_call(&self, session: &SessionEntry, frame: &Value) -> Dialed {
        let frame = match self.attest_where_owed(session, frame) {
            Ok(frame) => frame,
            Err(why) => return Dialed::from(why),
        };
        self.dial_reissuing(session, &frame)
    }

    /// Dials an attested frame, reissuing within the call.
    ///
    /// A reissue-class answer is reissued as [`classify`] bounds it — a
    /// `write_busy` once after [`WRITE_BUSY_WAIT`], a first and second
    /// `durability` as-is — and the first other answer returned: never a
    /// reissue. It is a first dial's dial, and the shifted dial's at a first
    /// dial ([`Holds::shift_at_first_dial`]).
    fn dial_reissuing(&self, session: &SessionEntry, frame: &AttestedWhereOwed<'_>) -> Dialed {
        let mut given = Reissues::default();
        loop {
            match self.dial(session, frame, &given) {
                Dialed::Reissue { kind, .. } => {
                    given.note(kind);
                    thread::sleep(kind.wait());
                }
                dialed => return dialed,
            }
        }
    }

    /// Holds an admitted burst for `reason`, as a dial's answer held it.
    ///
    /// The burst is taken, its frame the held line's own: the answer is the
    /// `held` answer ([`Holds::enter_line`]), or the hold's refusal, nothing
    /// held — `store_halted` where P38 halted the file, `held_full` where the
    /// principal's queue is full — and the `held` event is said under the
    /// board's lock ([`Holds::say_entered`]): the line's own face, or, where a
    /// line ahead of it on its document awaits the person's act, that line's
    /// state, kept in front, the hands it owes read once the lock is let go
    /// (skep #974). `failed` is the failed send the dial was, which starts
    /// the line's clock ([`held_failure`]; [`HAND_OVER_DEADLINE`]), none
    /// where the dial failed no send. `base` is
    /// the position the line's resend read starts from (§3c.2), the caller's
    /// to have read before its dial ([`Holds::send_burst`];
    /// [`PrincipalHold::base_of`]) — a hold made with no dial between reads
    /// it the same way, now. A burst the board refused as typed against an
    /// older state is held `moved`, its event naming the hands whose rows
    /// moved the document ([`Holds::hands_since_typed_state`]), read before
    /// the board's lock is taken, as every dial is made outside it; where
    /// that read meets the death signal, the burst is held at the death
    /// instead, its clock started by `failed` ([`Holds::hold_at_death`]), and
    /// the answer is [`OpAnswer::Died`] for the caller to end the session
    /// (§3c.4); where the board gives it no answer, the moved face stands on
    /// the verdict, its hands named not read ([`Hand::UNREAD`]), read again at
    /// the board's answer, and the board marked unanswered (skep #863); where
    /// the board answers it with no page they are named not read too, read
    /// again as the walk meets the document (skep #972), and where it has
    /// reclaimed the history the read asks for they are named `unknowable`
    /// ([`Hand::UNKNOWABLE`]), read again never (skep #989). The moved face
    /// names the verdict its hands were read for, the line entered and the
    /// board's refusal it carries ([`Judged`]; skep #973). A burst with no
    /// anchors held `moved` never shifts, so it is entered `sendable` false
    /// ([`Tested`]; skep #867).
    pub fn hold(&self, session: &SessionEntry, burst: Burst, reason: Reason, failed: Option<String>, base: u64) -> OpAnswer {
        let Some(HandsFace { hands, again, unanswered }) = self.hands_since_typed_state(session, &burst.doc, None, &reason).face() else { return self.hold_at_death(session, burst, failed, base) };
        let unanchored = burst.anchors.is_none();
        let read_for = reason.clone();
        let mut board_hold = self.lock(&session.board_reference);
        if unanswered {
            self.note_unanswered(&mut board_hold, None);
        }
        let entered = match self.enter_line(&mut board_hold, session, burst, reason, failed, base) {
            Ok(entered) => entered,
            Err(refusal) => return OpAnswer::Answered(Err(refusal)),
        };
        let judged = Judged::of(entered.k, &read_for);
        let mut face = MovedFace { hands: &hands, again, sendable: None, judged: judged.as_ref() };
        // A burst with no anchors never shifts (skep #867).
        if unanchored && entered.state == HeldState::Moved {
            if let Some(ph) = board_hold.principals.get_mut(&session.facts.principal) {
                ph.note_tested(&entered.doc, entered.k, Tested::Sendable(false), false);
                face.sendable = ph.sendable_told(&entered.doc);
            }
        }
        self.say_entered(board_hold, session, &entered, face);
        OpAnswer::Answered(Ok(entered.answer))
    }

    /// Holds an admitted burst whose first dial the board gave no answer to.
    ///
    /// It is §3c.4's hold at §3c.5's silence.
    ///
    /// `reason` is the dial's — `unreachable`, its `sent` whether the request
    /// may have left — and `refusal` its refusal. The line is entered so, no
    /// clock started: whether the dial was the line's own failure is the next
    /// `/health` verdict's (`Answering::Unanswered`), the send owed to it
    /// where its request may have left. The board is marked unanswered
    /// whatever the hold answers, so every burst after it is held at once
    /// until that verdict, and the `held` event says the line `holding`, or
    /// the state of a line ahead of it that awaits the person's act
    /// ([`Holds::say_entered`]; skep #974). The answer is the `held` answer,
    /// or the hold's refusal, nothing held ([`Holds::enter_line`]).
    fn hold_unanswered(&self, session: &SessionEntry, burst: Burst, reason: Reason, refusal: &Refusal, base: u64) -> OpAnswer {
        let principal = session.facts.principal;
        let sent = reason.sent;
        let mut board_hold = self.lock(&session.board_reference);
        let entered = self.enter_line(&mut board_hold, session, burst, reason, None, base);
        let cut = entered.as_ref().ok().filter(|_| sent).map(|entered| CutSend { principal, k: entered.k, doc: entered.doc.clone(), at: self.now(), refusal: refusal.to_string() });
        self.note_unanswered(&mut board_hold, cut);
        let entered = match entered {
            Ok(entered) => entered,
            Err(refusal) => return OpAnswer::Answered(Err(refusal)),
        };
        self.say_entered(board_hold, session, &entered, MovedFace::default());
        OpAnswer::Answered(Ok(entered.answer))
    }

    /// Holds an admitted burst at the death signal on its session's token.
    ///
    /// The signal was met at the burst's first dial, or at the moved hold's
    /// read of the hands after it (§3c.4): the line is entered `session_died`,
    /// `sent: false` — a dead token's write, and a stale one, landed nothing
    /// — its clock started where `failed` names the failed send the dial was
    /// ([`HAND_OVER_DEADLINE`]), and the `held` event says it `holding`, or
    /// the state of a line ahead of it that awaits the person's act
    /// ([`Holds::say_entered`]; skep #974), before the caller ends the
    /// session. The answer is [`OpAnswer::Died`] for the caller to end the
    /// session: the line's [`AtDeath::Held`], or [`AtDeath::Refused`] with
    /// what [`Holds::enter_line`] refused, nothing held.
    fn hold_at_death(&self, session: &SessionEntry, burst: Burst, failed: Option<String>, base: u64) -> OpAnswer {
        let mut board_hold = self.lock(&session.board_reference);
        OpAnswer::Died(match self.enter_line(&mut board_hold, session, burst, Reason::of(cause::SESSION_DIED, false), failed, base) {
            Ok(entered) => {
                self.say_entered(board_hold, session, &entered, MovedFace::default());
                AtDeath::Held(DeathHeld { k: entered.k, answer: entered.answer })
            }
            Err(refusal) => AtDeath::Refused(refusal),
        })
    }

    /// Holds one line before any dial, says so, and answers the call.
    ///
    /// Its birth is no failed send, so its clock is not started:
    /// `board_hold` is the session's board's hold under its lock, the line is
    /// entered ([`Holds::enter_line`]) and the `held` event said
    /// ([`Holds::say_entered`]), which lets the lock go. The answer is the
    /// `held` answer, its `cause` the line's own (skep #974).
    ///
    /// # Errors
    ///
    /// Returns what [`Holds::enter_line`] returns, nothing held.
    fn hold_line(&self, mut board_hold: MutexGuard<'_, BoardHold>, session: &SessionEntry, burst: Burst, reason: Reason, base: u64) -> Result<Value, Refusal> {
        let entered = self.enter_line(&mut board_hold, session, burst, reason, None, base)?;
        self.say_entered(board_hold, session, &entered, MovedFace::default());
        Ok(entered.answer)
    }

    /// Says the `held` event for a line just entered, and lets the lock go.
    ///
    /// `entered` is the line ([`LineEntered`]). The event says the line's own
    /// face — a moved line's `face`, the hands whose rows moved its document
    /// and its `sendable`, and no cause, as every moved document's face does,
    /// and any other line's cause — save
    /// where a line ahead of it on its document awaits the person's act
    /// ([`PrincipalHold::first_awaiting_act`]; skep #974): that line's state
    /// stays in front, said as [`Holds::say_standing`] says what stands, its
    /// count counting the new line. An own face naming the hands not read
    /// owes them to the walk ([`PrincipalHold::hands_owed`]). `board_hold` is
    /// the session's board's hold, its lock held since the line was entered,
    /// so the event goes out before any probe sends the line — `emit_held`
    /// touches the bus alone, so it is safe there — and let go before the
    /// event a standing face owes is said, its hands read first
    /// ([`Holds::say_with_hands`]).
    fn say_entered(&self, mut board_hold: MutexGuard<'_, BoardHold>, session: &SessionEntry, entered: &LineEntered, face: MovedFace<'_>) {
        let ph = board_hold.principals.get_mut(&session.facts.principal).expect("the principal's hold, entered by its door");
        let owed = if ph.first_awaiting_act(&entered.doc).is_some_and(|first| first != entered.k) {
            self.say_standing(session, ph, &entered.doc, None)
        } else {
            if face.hands.contains(&Hand::UNREAD) {
                ph.hands_owed.insert(entered.doc.clone(), entered.k);
            }
            let cause = (entered.state != HeldState::Moved).then_some(entered.cause.as_str());
            self.emit_held(session, &entered.doc, ph.lines_on(&entered.doc), entered.state, cause, face);
            None
        };
        drop(board_hold);
        if let Some(owed) = owed {
            self.say_with_hands(session, owed);
        }
    }

    /// Enters one line in the principal's queue at the session's board.
    ///
    /// `board_hold` is that board's hold. The line is the burst as stored,
    /// its frame carrying no attest and its anchors beside it, copied to its
    /// file where it has one, its `base` the caller's — the position of the
    /// principal's latest write on the document that the shell knew when the
    /// burst was sent, its ack's or the landing the resend's read found, or
    /// else the session's open position (§3c.2; [`PrincipalHold::base_of`]).
    /// The line is born here, by every path: where `failed` names the failed
    /// send its dial was ([`held_failure`]) — the person's own first dial's,
    /// a lost answer, a `poisoned` or `durability` hold, a second
    /// `write_busy`, a refused run or a move, shifted or not — its clock
    /// starts now ([`HAND_OVER_DEADLINE`]), and a hold before any dial, one
    /// no dial left by, or one at the death signal starts none.
    /// Nothing is said on the bus: the caller emits the `held` event, or none
    /// for a line it settles within its call ([`Holds::shift_at_first_dial`]);
    /// a wait for the held file's copies that begins or ends at this hold is
    /// said in the shell's own window ([`Holds::note_waiting`]). The answer
    /// is `{resp: held, held: <k>, cause}`, and `unwritable` beside it — why
    /// — with `unwritable_class`, its class ([`Unwritable`]), where no copy of
    /// the line stands: the device refused its copy, or a copy owed before it
    /// — an earlier line's, or a re-mark or a `done` of one — which it waits
    /// behind, its refusal's kind and words carried unchanged (§3c.3;
    /// `HeldQueue::retry`), or the device refused the store — the held
    /// directory or its lock, the file's read, the renumbering copy the read
    /// owed — so the queue's file is not yet read and every line of it waits
    /// (`HeldQueue::refuse`).
    ///
    /// # Errors
    ///
    /// Returns `store_halted` where the principal's file is halted
    /// ([`Holds::principal_hold`]); `another_window` where another shell
    /// holds the board's store — the burst passed the shell's write door
    /// before the state was found, and is refused as that door refuses one,
    /// nothing held (§3c.3; skep #828); and `held_full` where the
    /// principal's queue holds its budget already (`held::MAX_HELD_BYTES`'s
    /// bytes, its lines' frames and anchors, or `held::MAX_HELD_LINES`'s
    /// lines) or its ordinals are spent, and nothing held.
    fn enter_line(&self, board_hold: &mut BoardHold, session: &SessionEntry, burst: Burst, reason: Reason, failed: Option<String>, base: u64) -> Result<LineEntered, Refusal> {
        self.principal_hold(board_hold, session)?;
        if let Some(refusal) = another_window(board_hold, &burst) {
            return Err(refusal);
        }
        let now = self.now();
        let moment = Moment { at: now, answering: board_hold.answering_at(now) };
        let ph = board_hold.principals.get_mut(&session.facts.principal).expect("the principal's hold, entered by its door");
        let (doc, frame, anchors) = burst.into_stored();
        let id = frame["id"].as_str().map(str::to_owned);
        let state = line_state(&reason);
        let cause = reason.cause.clone();
        let entered = ph.hold(&doc, id.as_deref(), base, frame, anchors, reason).map_err(queue_refused)?;
        if let Some(token) = failed {
            ph.reissues.entry(entered.k).or_default().failed(token, moment);
        }
        self.note_waiting(session.facts.principal, ph);
        let mut answer = json!({"resp": "held", "held": entered.k, "cause": cause});
        if let Some(why) = entered.unwritten.as_ref().map(Unwritable::from) {
            why.answer_in(&mut answer);
            ph.unwritable_docs.insert(doc.clone());
        }
        Ok(LineEntered { k: entered.k, answer, doc, state, cause })
    }

    /// Gives a burst held at the death signal the death's reason, and
    /// returns the call's answer (§3c.4; §4b.2's arms).
    ///
    /// `died` is the `session_died` refusal the session's end answered
    /// (`Sessions::end`), its `reason` naming the death's arm. The line takes
    /// it as its refusal, its cause and its `sent` kept, while it stands as
    /// the death held it — `session_died`, no refusal beside it: a line the
    /// probe resent since, under the session that stands, is the resend's to
    /// settle and is left alone. A copy refused is owed, or said on `Talk`,
    /// as every re-mark's is ([`Holds::remark_line`]). The answer is the
    /// `held` answer the hold made of the burst.
    pub fn note_death(&self, session: &SessionEntry, held: DeathHeld, died: &Refusal) -> Value {
        let DeathHeld { k, answer } = held;
        self.with_principal(&session.board_reference, session.facts.principal, |ph| {
            let standing = ph.queue.line(k).filter(|l| l.reason.cause == cause::SESSION_DIED && l.reason.refusal.is_none()).map(|l| l.reason.sent);
            if let Some(sent) = standing {
                self.remark_line(session.facts.principal, ph, k, Reason { cause: cause::SESSION_DIED.to_string(), refusal: Some(died.to_value()), sent });
            }
        });
        answer
    }

    /// Notes an acked session write (§3c.2, §3c.5).
    ///
    /// Its `at` enters the board's acked positions ([`BoardHold::acked`]),
    /// whatever documents its row names, and becomes the `base` of the next
    /// hold on every document its row names where it is past the position
    /// noted there, which stands otherwise ([`PrincipalHold::note_position`])
    /// — whatever its kind, a burst's, a mint's or a link's, the first dial's
    /// and the resend's alike, each noted where its answer is read. An
    /// arrangement write's — a burst's or a `set_arrangement`'s — is the
    /// position of the principal's latest arrangement write on its `doc`
    /// too, where it is past the one noted there
    /// ([`PrincipalHold::note_arranged`]). An insert's carrying an `id` is
    /// entered among the principal's landed inserts with the address its ack
    /// minted ([`PrincipalHold::note_landed_insert`], [`minted_by`]), so a
    /// later burst's anchors can name its words (skep #969). No standing line
    /// is touched: a line held keeps the base it was held at. A read, or a
    /// refusal, notes nothing.
    fn note_ack(&self, session: &SessionEntry, frame: &Value, ack: &Value) {
        let Some(at) = acked_at(ack) else { return };
        let landed = minted_by(frame, ack).map(|minted| (frame, minted));
        self.note_written(session, at, &written_docs(frame, ack), arranged_doc(frame), landed);
    }

    /// Notes a restore `session` made: the `history.restore` row's write
    /// (B3-S7; P3).
    ///
    /// The restore's one `set_arrangement` is the library's
    /// (`skep_client::history::restore`), dialed outside [`Holds::send`], and
    /// is noted as [`Holds::note_ack`] notes an acknowledged
    /// `set_arrangement`: its position enters the board's acked positions
    /// ([`BoardHold::acked`]), becomes the `base` of the next hold on the
    /// draft where it is past the position noted there
    /// ([`PrincipalHold::note_position`]), and is the principal's latest
    /// arrangement write on the draft ([`PrincipalHold::note_arranged`]) —
    /// the editor's own last ack a merge's undo is typed against
    /// ([`Holds::last_arranged`]), so a restore of the person's never stands
    /// as another hand's change under it.
    ///
    /// # Panics
    ///
    /// Panics where the session's board is none the holds were opened over
    /// (the type's precondition).
    pub fn note_restored(&self, session: &SessionEntry, restored: &Restored) {
        self.note_arranged(session, &restored.draft.to_string(), restored.position);
    }

    /// Notes a whole-draft write `session` made through the merge library.
    ///
    /// It is a draft landing's, an undo's, a withdrawal's or a withdrawal's
    /// undo's one `set_arrangement` at `at` (skep #870; P3).
    ///
    /// Each is dialed outside [`Holds::send`], as the restore's is, and is
    /// noted as [`Holds::note_restored`] notes the restore's: the editor's
    /// own last ack on `draft` the next undo or withdrawal's undo is typed
    /// against ([`Holds::last_arranged`]), so the family's own writes never
    /// stand as another hand's change under it.
    ///
    /// # Panics
    ///
    /// Panics where the session's board is none the holds were opened over
    /// (the type's precondition).
    pub fn note_arranged(&self, session: &SessionEntry, draft: &str, at: u64) {
        self.note_written(session, at, &[draft], Some(draft), None);
    }

    /// Notes `at`, the position of a write of the session's principal's.
    ///
    /// It enters the board's acked positions, raises the `base` on each of
    /// `docs`, the documents its row names, and, where the write set
    /// `arranged`'s arrangement, the principal's latest arrangement write
    /// there, and where `landed` names an insert's frame and the address its
    /// ack minted, the insert among the principal's landed inserts
    /// ([`Holds::note_ack`]'s and [`Holds::note_restored`]'s one body).
    fn note_written(&self, session: &SessionEntry, at: u64, docs: &[&str], arranged: Option<&str>, landed: Option<(&Value, &str)>) {
        let mut board_hold = self.lock(&session.board_reference);
        board_hold.acked.insert(at);
        if docs.is_empty() {
            return;
        }
        let pending = HeldDir::pending(&self.data_dir, session.board.dialed());
        let ph = board_hold.principals.entry(session.facts.principal).or_insert_with(|| PrincipalHold::new(session.facts.account.as_deref().unwrap_or(""), &pending, session.facts.principal));
        for &doc in docs {
            ph.note_position(doc, at);
        }
        if let Some(doc) = arranged {
            ph.note_arranged(doc, at);
        }
        if let Some((frame, minted)) = landed {
            ph.note_landed_insert(frame, minted);
        }
    }

    /// Returns the position of the principal's latest arrangement write on
    /// `doc` at the session's board, where the shell knows one (P3).
    ///
    /// It is [`PrincipalHold::last_arranged`]'s, read under the board's lock,
    /// no hold opened: the position `merge.undo` hands the library's undo as
    /// the editor's own last acknowledgment on the draft
    /// (`skep_client::merge::undo`). `None` where no arrangement write of the
    /// principal's on `doc` was acknowledged through this shell — through
    /// `op`, or a restore's ([`Holds::note_restored`]) — or found landed by
    /// its resend.
    ///
    /// # Panics
    ///
    /// Panics where the session's board is none the holds were opened over
    /// (the type's precondition).
    pub fn last_arranged(&self, session: &SessionEntry, doc: &str) -> Option<u64> {
        self.with_principal(&session.board_reference, session.facts.principal, |ph| ph.last_arranged.get(doc).copied()).flatten()
    }

    /// Returns whether this shell acked a write at `at` on the board.
    ///
    /// It is the resend's landed test's question of a row
    /// ([`BoardHold::acked`]): a row at an acked position is a write this
    /// shell was answered for, never a line's lost landing.
    fn acked(&self, board_reference: &str, at: u64) -> bool {
        self.lock(board_reference).acked.contains(&at)
    }

    /// Answers `held(session)`: the acting principal's held lines at its board.
    ///
    /// They come in resend order (§4b.1), from this principal's file and no
    /// other (P39). Each line of a document that stands moved names the
    /// hands of the verdict the document stands on now (`hands`), and whether
    /// they are named `again`, as a `moved` event names them (skep #973,
    /// #989): the lines behind the one the verdict rides were moved by the
    /// same writes. They are those the session's memory holds for that
    /// verdict, named with no read; else read for this session once the
    /// board's lock is let go ([`Holds::read_listed_hands`]), the lock taken
    /// again to build the rows. What the rows name is entered in the
    /// session's memory as a `moved` face for that verdict, saying no event
    /// ([`Holds::remember`]). Where no page named the hands — the read went
    /// unanswered, was answered with no page or met the death signal, or
    /// none was made at a board not answering or an own node stopped, or the
    /// document moved again while the read was out — the rows name them
    /// `unread`, and the document owes them to the walk
    /// ([`PrincipalHold::hands_owed`]), which names them to the session as
    /// the board answers; where the board has reclaimed the history the read
    /// asks for, the rows name them `unknowable`, and none is owed.
    ///
    /// **Its cost** (SP-23): one `/changes` page for each document that
    /// stands moved on a verdict the session's memory holds no face for, or
    /// two where the board refused its burst again with no row since the
    /// person's `send` ([`Holds::hands_since_typed_state`]), and the key
    /// labels of an account a hand of another device's belongs to, read once
    /// per account (`labels`); none at a board not answering or an own node
    /// stopped, and none after a read the board gave no answer to. The death
    /// signal a read meets is met again at the session's next request.
    ///
    /// # Errors
    ///
    /// Returns `store_halted` where P38 halted the file, at the principal's
    /// door before the reads or after them.
    ///
    /// # Panics
    ///
    /// Panics where the session's board is none the holds were opened over
    /// (the type's precondition).
    pub fn lines(&self, session: &SessionEntry) -> Result<Value, Refusal> {
        let board_reference = session.board_reference.as_str();
        // The moved documents whose hands the session's memory holds for no
        // verdict they stand on now, read once the lock is let go.
        let owed = {
            let mut board_hold = self.lock(board_reference);
            let ph: &PrincipalHold = self.principal_hold(&mut board_hold, session)?;
            let mut owed: Vec<(String, u64, Reason)> = ph.queue.docs().filter_map(|doc| self.hands_owed_to(session, ph, doc).map(|(k, reason)| (doc.to_string(), k, reason))).collect();
            owed.sort_by_key(|(_, k, _)| *k);
            owed
        };
        let mut read = self.read_listed_hands(session, owed);
        let mut board_hold = self.lock(board_reference);
        let ph = self.principal_hold(&mut board_hold, session)?;
        let docs: Vec<String> = ph.queue.docs().map(str::to_owned).collect();
        // The face each moved document's moved rows name, by the document.
        let mut named: HashMap<String, HeldSaid> = HashMap::new();
        for doc in docs {
            let Some(judged) = ph.judged_on(&doc) else { continue };
            let face = match self.told(session, &doc).filter(|told| told.moved_for(Some(&judged))) {
                Some(face) => face,
                None => {
                    // The hands a read named for the line standing at the head
                    // as it was read, else none read yet for its verdict.
                    let stands = |(k, reason, _): &(u64, Reason, HandsFace)| *k == judged.k && ph.queue.reason(*k) == Some(reason);
                    let read = read.remove(&doc).filter(stands).map_or_else(HandsFace::not_read, |(_, _, read)| read);
                    let sendable = if session.may_write() { ph.queue.line(judged.k).and_then(|line| ph.sendable_of(&line)) } else { None };
                    let face = MovedFace { hands: &read.hands, again: read.again, sendable, judged: Some(&judged) };
                    self.remember(session, &doc, HeldSaid::of(ph.lines_on(&doc), HeldState::Moved, None, face))
                }
            };
            if face.hands.contains(&Hand::UNREAD) {
                ph.hands_owed.insert(doc.clone(), judged.k);
            }
            named.insert(doc, face);
        }
        // The keyless session's `send` is refused (§4b.1): it reads no mark.
        let may_write = session.may_write();
        let unwritable = ph.queue.waiting().map(|waiting| Unwritable::from(&waiting.refusal()));
        let row = |line: &HeldLine| {
            let sendable = may_write.then(|| ph.sendable_of(line)).flatten();
            let face = named.get(&line.doc).filter(|_| line.reason.cause == cause::MOVED);
            line_json(line, sendable, face, unwritable.as_ref().filter(|_| ph.queue.off_disk(line.k)))
        };
        Ok(Value::Array(ph.queue.lines().iter().map(row).collect()))
    }

    /// Reads the hands of each moved document `owed` names, for `session`.
    ///
    /// It is the held list's reads ([`Holds::lines`]; skep #973), made with no
    /// lock held, each as a moved face's is
    /// ([`Holds::hands_since_typed_state`]) for the line the verdict rides and
    /// its reason as the list's first pass found them, and only while the
    /// board answers and the own node runs (§3c.5). A read the board gives no
    /// answer to marks it unanswered, and no read is made after it, nor after
    /// the death signal. Each document is answered beside the line read for,
    /// the face its read names ([`HandsRead::face`]): the hands a page named,
    /// `again` where they are those the person's last `send` acknowledged,
    /// the one hand `unknowable` where the board has reclaimed the history,
    /// else the one hand `unread`.
    ///
    /// # Panics
    ///
    /// Panics where the session's board is none the holds were opened over
    /// (the type's precondition).
    fn read_listed_hands(&self, session: &SessionEntry, owed: Vec<(String, u64, Reason)>) -> HashMap<String, (u64, Reason, HandsFace)> {
        let board_reference = session.board_reference.as_str();
        let mut reads = true;
        let dials = || {
            let board_hold = self.lock(board_reference);
            board_hold.answers() && !board_hold.node_stopped
        };
        owed.into_iter()
            .map(|(doc, k, reason)| {
                let read = (reads && dials()).then(|| self.hands_since_typed_state(session, &doc, Some(k), &reason));
                reads &= !matches!(read, Some(HandsRead::Unanswered | HandsRead::Died));
                let face = read.and_then(HandsRead::face).unwrap_or_else(HandsFace::not_read);
                if face.unanswered {
                    self.note_unanswered(&mut self.lock(board_reference), None);
                }
                (doc, (k, reason, face))
            })
            .collect()
    }

    /// Enters `said`, a `moved` face the held list named, in the memory.
    ///
    /// It is `session`'s memory of `doc` ([`Holds::last_emitted`]), and no
    /// event is said: the list tells what it names on its rows (skep #973).
    /// A `moved` face for the same verdict the memory holds — one an event
    /// told the session while the list read — stands; else `said` is
    /// entered. It answers the face that stands.
    ///
    /// # Panics
    ///
    /// Panics where the memory's lock is poisoned.
    fn remember(&self, session: &SessionEntry, doc: &str, said: HeldSaid) -> HeldSaid {
        let key = (session.board_reference.clone(), session.reference.clone(), doc.to_string());
        let mut last = self.last_emitted.lock().expect("the held events' memory");
        if let Some(told) = last.get(&key).filter(|told| told.moved_for(said.judged.as_ref())) {
            return told.clone();
        }
        last.insert(key, said.clone());
        said
    }

    /// Answers `held.show(session)`, the halt face's own act (§3c.3).
    ///
    /// The act is "show the file". The session names the principal, so a
    /// page shows its own principal's file and learns nothing of another's
    /// (P39), and the principal's door is taken as every act takes it. Where
    /// P38 halted the file, the file is shown in the shell's own window
    /// ([`halted_line`]: its path, why it is halted and the act its why asks)
    /// as often as the person asks — each line the answer to their act, never
    /// the standing halt said again (SP-11) — and the answer is true; nothing
    /// is said and the answer is false otherwise. The path goes to `Talk`
    /// alone, never to the page (§4b.3; SP-15).
    pub fn show_halted(&self, session: &SessionEntry) -> bool {
        let mut board_hold = self.lock(&session.board_reference);
        // The door opens the principal's file where it is not yet read; its
        // refusal is the halt read from the custody below.
        let _ = self.principal_hold(&mut board_hold, session);
        let Some((path, why)) = board_hold.halted(session.facts.principal) else { return false };
        self.say(halted_line(session.facts.principal, path, why));
        true
    }

    /// Answers `resolve(session, {held, act})` (§3c.4, §4b.1).
    ///
    /// It is checked and acted on under the board's one lock, save the drop
    /// that reads first, whose read is made outside it, and the read of the
    /// hands a drop's `held` event owes, made once the act is done (below).
    /// [`ResolveAct::Drop`] marks the line and every line held after it on
    /// that document — a refused run's `behind` lines, a moved document's
    /// later lines, the lines held behind a holding one — `done … dropped`;
    /// [`ResolveAct::Send`] re-marks the
    /// document's waiting lines `behind`, each keeping its `sent`, its clock
    /// started afresh at its next failed send ([`HAND_OVER_DEADLINE`]),
    /// handing them back to the automatic machine, and answers at once
    /// ([`Resolved::HandedBack`]): the probe that resends them is the
    /// caller's to hand the board's feed thread. Either act's lines are one
    /// run, written to the held file as one copy with one sync however many
    /// it settles or re-marks ([`Holds::drop_run`], [`Holds::remark_lines`];
    /// skep #861).
    ///
    /// **The raise** (§3c.4; skep #757, #989). On a moved document the send
    /// first raises each waiting line's `base` to the position the board's
    /// verdict read through — the `site.current` of its `arrangement_moved`,
    /// kept on the line it refused — a base already past it standing, the
    /// raise written to the held file with the line's re-mark
    /// (`HeldQueue::remark_all`), a copy the device refuses owed as every
    /// re-mark's is. The act is the person's acknowledgment of the rows that
    /// moved the document: each line's read for its own landing starts past
    /// them, and a document held moved again names only the hands since
    /// ([`PrincipalHold::seen_through`]); held moved again with no row since,
    /// the board refusing a burst again for the change the person
    /// acknowledged, it names again the hands the acknowledged face named,
    /// marked `again` ([`PrincipalHold::acknowledged`]). A document no line
    /// of which carries such a verdict is raised nothing. The lines then
    /// re-enter as every line does: the read, then the send — a stale send
    /// shifted where its span is whole, else held moved again.
    ///
    /// **No landing is passed over.** A head that landed among the rows the
    /// raise passes over was kept before the verdict was given: a document
    /// is held moved by the board's verdict on a dial alone, and every
    /// resend of a line that may have landed is preceded by the read for its
    /// own landing from its base (§3c.5), so a landing that read could keep
    /// was kept first, and the rows the verdict read through hold none. One
    /// no read can keep — its row's testimony lost, of a kind no read
    /// confirms — is judged as every resend is, by the board's typed state
    /// and the shift's test of the span, raised or not.
    ///
    /// **The drop of a holding line** (skep #726, #983). A line held where a
    /// resend follows — the board away, the own node stopped, the writes
    /// halted, a second `write_busy`, a third `durability`, the board's head
    /// record not reading, the death signal at its dial — awaits no act of
    /// the person's: the probe sends it as the board takes it, so `send` on
    /// it stays `not_resolvable`. The drop is admitted all the same, the
    /// person's discard of words the board may never have had: a run of
    /// typing the person takes back while it is held, or a write held for a
    /// head record the board may never repair, which would otherwise stand,
    /// and fill the queue, for good. It drops the line and every later line
    /// of its document, as a refused run's drop does, though `client.md`'s
    /// `resolve` row names that reach for a refused run and a moved document
    /// alone (a word owed to it): a later burst on the document was composed
    /// against the page's text with the dropped burst in it, and the board
    /// cannot see that — its typed state never moved for a burst that never
    /// landed — so sent alone it would land off; the page re-composes them
    /// from its editor's text, as at any drop. In `resolve` alone:
    /// [`awaits_act`] and [`line_state`] stand as they are, so the probe
    /// sends every holding line no drop takes.
    ///
    /// **The discard under the keyless session** (§4b.1's `resolve` row;
    /// foundations §3.3 state 3; skep #896). Under a session that may not
    /// write ([`SessionEntry::may_write`]) — the keyless session, which reads
    /// the held file and sends nothing — the drop is admitted on every line
    /// of its principal's, in any state: no resend follows under it, so a
    /// line held for a key the device no longer holds, one another hand
    /// retired among them, waits for good unless the person discards it. It
    /// drops the line and every later line of its document, as every drop
    /// does, and writes the held file alone, nothing to the board. No resend
    /// overtakes it, though the hold asks the acting session's kind alone: a
    /// shell's sessions all open in its run's one mode, and the restart arm
    /// re-opens a signed session alone, so where a bare session acts no
    /// session of its principal that may write stands and no drain walks the
    /// line. The shell's row refuses `send` under it before it reaches here
    /// (`write_in_bare_session`).
    ///
    /// **The drop of a line that may have landed** (§3c.4, §3c.5; skep #866,
    /// #983). A line marked `sent` that is holding, or that the shell handed
    /// the person under `answers_lost`, may stand on the board: a dial the
    /// client gave up on commits late, and a `poisoned` commit is rebuilt
    /// from the journal at the board's restart. So its drop under a session
    /// that may write reads for the line's landing first, as a resend does
    /// (`resend`'s `read_outcome`), and never drops words the board is found
    /// to hold ([`reads_first`]). A line no dial of which may have left the
    /// device — its every dial a connection never made, a refusal, or
    /// another answer that committed nothing ([`PrincipalHold::never_left`])
    /// — is read for nothing, whatever its `sent` says. No read is made where
    /// a hold stands at the board or the board is not answering
    /// (`BoardHold::landing_unreadable`): the drop is refused. The read is
    /// made outside the board's lock, and its outcome acted on under the
    /// lock again, the door taken again and the line asked to stand with the
    /// reason it was read under, taken by no send since: a landing found
    /// keeps the line `done kept` as the resend keeps a landed head
    /// ([`Holds::keep_landing`]), nothing dropped, the `held` event naming
    /// the line and the position the read found it at (skep #968), the lines
    /// behind it handed to the machine as a `send`'s are ([`Resolved::Kept`]);
    /// no row that could be its landing drops it, as every drop does; the
    /// death signal drops nothing ([`Resolved::Died`]); and where the read
    /// cannot tell — no answer, no page, a row that could be the landing and
    /// is not confirmed — nothing is dropped and the drop is refused, a board
    /// the read went unanswered at marked so until a `/health` answers. A
    /// line handed over leaves by `send` there, whose dial the board judges
    /// by its typed state; a holding one is sent by the probe as every
    /// holding line is, and its drop answers again once that send keeps the
    /// line or holds it moved, a moved line's drop reading nothing. A drop of
    /// a line never sent, a refused run's or a moved document's other drops,
    /// and the keyless session's discard, whose rows are never its own, make
    /// no read.
    ///
    /// **The lines a drop names** (§3c.4; skep #993). Every drop answers the
    /// lines it took that may have landed ([`PrincipalHold::may_have_landed`])
    /// and that no read of its own ruled out, in `k` order
    /// ([`Resolved::Dropped`]): a refused run's or a moved document's line
    /// marked `sent` — a resend whose read could not decide its landing, then
    /// refused — the keyless session's discard of a `sent` line, and a `sent`
    /// line behind the one a drop that read first found unlanded. The lines
    /// are dropped all the same, the discard the person's; the answer says
    /// that their words may already stand on the board, which the feed's next
    /// `drafts` row and the next `image` read show where they do.
    ///
    /// **No act while a dial is out** (skep #983). A line a send has taken
    /// for its dials ([`PrincipalHold::dialing`]) — the walk's resend of it,
    /// or a first dial's shift within its call — takes neither act: the
    /// dial's answer keeps the line or re-marks it, and an act made meanwhile
    /// would act on a line that answer then finds gone or moved. A drop whose
    /// read was out as a send took the line acts on nothing at the lock
    /// after the read, the line's sends counted ([`Reissues::outs`]): the
    /// read may not have seen that send's write.
    ///
    /// **The hands a drop's event names** (§4b.2's `held` event; skep #960).
    /// A drop that leaves its document moved says it `moved` again, naming
    /// the hands the last face told the acting session named. Where the
    /// session was told no moved face of it — re-opened since, another of the
    /// principal's, or told a burst held behind — the event is owed, and said
    /// once every lock the act took is let go, the hands read first
    /// (`Holds::say_with_hands`): the act and its answer stand whatever that
    /// read meets, and no read is made at a board that is not answering or an
    /// own node stopped, the hands then named not read.
    ///
    /// # Errors
    ///
    /// Its refusals come in this order, the first that holds answering:
    ///
    /// 1. `store_halted` where P38 halted the principal's file;
    /// 2. `no_such_held` where no line of ordinal `k` stands;
    /// 3. `not_resolvable` where a send has the line out for its dials, and
    ///    for a `send` where the line awaits no act of the person's (P10);
    /// 4. for a drop that reads first, before its read: `landing_unread`
    ///    `{held, why}`, `why` `stopped`, `poisoned` or `halted` where that
    ///    hold stands at the board, else `unanswered` where the board is not
    ///    answering;
    /// 5. after its read: `landing_unread` with `why` `unanswered` where the
    ///    board gave it no answer, `unread` where it answered no page, and
    ///    `undecided` where a row could be the line's landing and is not
    ///    confirmed;
    /// 6. at the check under the lock again: `store_halted`, `no_such_held`,
    ///    and `not_resolvable` where the line was re-marked, or taken for a
    ///    send's dials, while the read was out.
    pub fn resolve(&self, session: &SessionEntry, k: u64, act: ResolveAct) -> Result<Resolved, Refusal> {
        let (resolved, owed) = self.resolve_line(session, k, act)?;
        // Every lock the act took is let go: the hands are read outside them.
        if let Some(owed) = owed {
            self.say_with_hands(session, owed);
        }
        Ok(resolved)
    }

    /// Acts on line `k` as [`Holds::resolve`] does, and answers the act.
    ///
    /// The answer is the act's outcome, and the `held` event the act owes
    /// where its document stands moved and no face told the session named
    /// the hands ([`HandsOwed`]): the act says every other event itself,
    /// under the board's lock.
    ///
    /// # Errors
    ///
    /// Returns what [`Holds::resolve`] refuses, in its order.
    fn resolve_line(&self, session: &SessionEntry, k: u64, act: ResolveAct) -> Result<(Resolved, Option<HandsOwed>), Refusal> {
        let principal = session.facts.principal;
        let (read, outs) = {
            let mut board_hold = self.lock(&session.board_reference);
            let ph = self.principal_hold(&mut board_hold, session)?;
            let line = resolvable(ph, k, act)?;
            if !reads_first(ph, &line, act, session) {
                return Ok(self.act_at_once(session, ph, k, &line.doc, act));
            }
            // The sends that have taken the line, which the check after the
            // read holds to (skep #983).
            let outs = ph.outs(k);
            if let Some(why) = board_hold.landing_unreadable() {
                return Err(landing_unread(k, why));
            }
            (line, outs)
        };
        // Outside the lock, as every dial is: the read takes it itself.
        let outcome = self.read_outcome(session, &read.doc, &read);
        let mut board_hold = self.lock(&session.board_reference);
        let why = match outcome {
            ReadOutcome::Died => return Ok((Resolved::Died, None)),
            ReadOutcome::Unanswered => {
                self.note_unanswered(&mut board_hold, None);
                LandingUnread::Unanswered
            }
            ReadOutcome::Unread => LandingUnread::Unread,
            ReadOutcome::Undecided => LandingUnread::Undecided,
            ReadOutcome::Landed { at, minted } => {
                self.still_as_read(&mut board_hold, session, &read, outs)?;
                self.keep_landing(&mut board_hold, principal, &read, at, minted.as_deref());
                let ph = board_hold.principals.get_mut(&principal).expect("the principal's hold, entered by its door");
                // A pass under way walks the document again at its next turn.
                ph.stopped_in_pass.remove(&read.doc);
                ph.cut_in_pass.remove(&read.doc);
                let owed = self.say_standing(session, ph, &read.doc, Some(&LandedLine::of(&read, at, None)));
                return Ok((Resolved::Kept, owed));
            }
            ReadOutcome::NoLanding => {
                let ph = self.still_as_read(&mut board_hold, session, &read, outs)?;
                // The read ruled out the line's own landing, and no other.
                let may_have_landed = self.drop_run(principal, ph, k, &read.doc).into_iter().filter(|&landed| landed != k).collect();
                let owed = self.say_standing(session, ph, &read.doc, None);
                return Ok((Resolved::Dropped { may_have_landed }, owed));
            }
        };
        Err(landing_unread(k, why))
    }

    /// Returns the principal's hold where line `read.k` stands as read.
    ///
    /// It is the drop's check under the lock again after its read
    /// ([`Holds::resolve`]): the principal's door taken again, and the line
    /// asked to stand with the reason the read was made under, taken by no
    /// send since, `outs` the sends that had taken it as the read began
    /// ([`Reissues::outs`]; skep #983).
    ///
    /// # Errors
    ///
    /// Returns `store_halted` where P38 halted the principal's file,
    /// `no_such_held` where no line of the ordinal stands, and
    /// `not_resolvable` where the line was re-marked while the read was out —
    /// a `send` of it, whose resend the drop's read says nothing of — or a
    /// send took it for its dials meanwhile, whose write the read may not
    /// have seen, the line's reason as it stood or not.
    fn still_as_read<'b>(&self, board_hold: &'b mut BoardHold, session: &SessionEntry, read: &HeldLine, outs: u64) -> Result<&'b mut PrincipalHold, Refusal> {
        let ph = self.principal_hold(board_hold, session)?;
        let as_read = ph.queue.reason(read.k).map(|reason| *reason == read.reason && ph.outs(read.k) == outs);
        match as_read {
            None => Err(Refusal::shell(Name::NO_SUCH_HELD, json!({"held": read.k}))),
            Some(false) => Err(Refusal::shell(Name::NOT_RESOLVABLE, json!({"held": read.k}))),
            Some(true) => Ok(ph),
        }
    }

    /// Acts on line `k` at once, under the board's lock: the drop or the send.
    ///
    /// It is every act save the drop that reads first ([`Holds::resolve`]),
    /// answered beside the `held` event a drop owes ([`Holds::say_standing`]):
    /// a drop that read nothing names every line it took that may have landed
    /// (skep #993).
    fn act_at_once(&self, session: &SessionEntry, ph: &mut PrincipalHold, k: u64, doc: &str, act: ResolveAct) -> (Resolved, Option<HandsOwed>) {
        match act {
            ResolveAct::Drop => {
                let may_have_landed = self.drop_run(session.facts.principal, ph, k, doc);
                (Resolved::Dropped { may_have_landed }, self.say_standing(session, ph, doc, None))
            }
            ResolveAct::Send => {
                // Re-enter the automatic machine (§3c.4): the document's
                // waiting lines re-marked `behind`, each keeping its `sent` —
                // the read takes a landing it finds as the line's own only
                // where `sent` stands, so a line that may have landed reads
                // before it is sent again (§3c.5) — their clocks cleared, so
                // each starts afresh at the line's next failed send, the read
                // run at the next probe, and the refusal faced again where it
                // recurs; the reissues given stand. On a moved document each
                // is raised first, and written so, to the position the board's
                // verdict read through — `site.current`, on the line the board
                // refused — the rows up to it the ones the act acknowledges:
                // the read starts past them, none of them a landing the read
                // before the verdict's dial could keep, and their hands are
                // named no more, save by a face the board's refusal of the
                // same change again gives, read from where the acknowledged
                // face read them (skep #989). A document whose lines carry no
                // such verdict is re-marked as it stands. The re-marks are one
                // run, one copy (skep #861).
                let waiting: Vec<(u64, bool)> = ph.queue.reasons_on(doc).filter(|(_, reason)| awaits_act(reason)).map(|(k, reason)| (k, reason.sent)).collect();
                let verdict = ph.queue.reasons_on(doc).filter(|(_, reason)| reason.cause == cause::MOVED).find_map(|(judged, reason)| {
                    let site = &reason.refusal.as_ref()?["site"];
                    Some((judged, site["current"].as_u64()?, site["as_of"].as_u64()))
                });
                let seen = verdict.map(|(judged, through, typed)| ph.acknowledged(judged, through, typed));
                self.remark_lines(session.facts.principal, ph, waiting.iter().map(|&(k, sent)| (k, Reason::of(cause::BEHIND, sent))), seen.map(|seen| seen.through));
                for &(k, _) in &waiting {
                    if let Some(seen) = seen {
                        let entry = ph.seen_through.entry(k).or_insert(seen);
                        *entry = Seen { through: entry.through.max(seen.through), from: seen.from };
                    }
                    if let Some(given) = ph.reissues.get_mut(&k) {
                        given.first_failed = None;
                        given.last = None;
                    }
                }
                // A pass under way walks the document again at its next turn,
                // and its moved face, gone, owes no hands and no shift test.
                ph.stopped_in_pass.remove(doc);
                ph.cut_in_pass.remove(doc);
                ph.hands_owed.remove(doc);
                ph.shift_tests.remove(doc);
                (Resolved::HandedBack, None)
            }
        }
    }

    /// Drops the line `from` and every line after it on that document.
    ///
    /// The `"drop"` marks them — a refused run's `behind` lines, a moved
    /// document's later lines — `done … dropped`, as one run, its `done`s one
    /// copy with one sync however many lines it drops ([`Holds::done_lines`];
    /// skep #861), the file compacting where the queue empties. It answers
    /// the lines of the run that may have landed, in `k` order
    /// ([`PrincipalHold::may_have_landed`]; skep #993).
    fn drop_run(&self, principal: u64, ph: &mut PrincipalHold, from: u64, doc: &str) -> Vec<u64> {
        let ks: Vec<u64> = ph.queue.reasons_on(doc).map(|(k, _)| k).filter(|&k| k >= from).collect();
        // Read before the settle, which forgets each line's reason and its
        // place among the lines no dial of which left.
        let may_have_landed = ph.queue.reasons_on(doc).filter(|&(k, reason)| k >= from && ph.may_have_landed(k, reason)).map(|(k, _)| k).collect();
        self.done_lines(principal, ph, &ks, Done::Dropped);
        may_have_landed
    }

    /// Emits the `held` event for what stands on `doc` after a person's act.
    ///
    /// It says what stands under the session that acted, the hands as the
    /// session was told them ([`Holds::say_as_told`]), save where the act
    /// left `doc` moved on the board's verdict and the last face told the
    /// session of it is no `moved` face for that verdict: no face it was told
    /// names the hands, so it says nothing and answers the event owed, said
    /// once the board's lock is let go with the hands read ([`HandsOwed`];
    /// skep #960, #973). It says the same where a line is entered, kept or
    /// re-marked behind a first line that awaits the person's act, whose
    /// state stays in front ([`Holds::say_entered`],
    /// [`Holds::say_standing_ahead_of`]; skep #974).
    #[must_use = "an event owed is said by `Holds::say_with_hands` once the board's lock is let go"]
    fn say_standing(&self, session: &SessionEntry, ph: &mut PrincipalHold, doc: &str, landed: Option<&LandedLine>) -> Option<HandsOwed> {
        if let Some((k, reason)) = self.hands_owed_to(session, ph, doc) {
            return Some(HandsOwed { doc: doc.to_string(), k, reason, landed: landed.cloned() });
        }
        self.say_as_told(session, ph, doc, landed);
        None
    }

    /// Returns the head line a moved face of `doc` owes `session` its hands by.
    ///
    /// It is skep #960's, #972's and #973's debt: the document's first line,
    /// with its reason, where that line
    /// carries the board's verdict ([`Judged::of`]) and the session's memory
    /// of `doc` holds no `moved` face for it: no face it was told, or the
    /// held list named, names that verdict's hands, an earlier move's among
    /// those it does not. It answers none otherwise — a face of the session's
    /// names them, or no read could.
    fn hands_owed_to(&self, session: &SessionEntry, ph: &PrincipalHold, doc: &str) -> Option<(u64, Reason)> {
        let (k, reason) = ph.queue.reasons_on(doc).next()?;
        let judged = Judged::of(k, reason)?;
        if self.told(session, doc).is_some_and(|told| told.moved_for(Some(&judged))) {
            return None;
        }
        Some((k, reason.clone()))
    }

    /// Emits the `held` event for what stands on `doc`, its hands as told.
    ///
    /// It says what stands ([`state_on`]) under `session`, a moved face its
    /// `sendable`, none under the keyless session, which is offered no
    /// `send` (§4b.1), the verdict it stands on and the hands the session's
    /// memory holds for that verdict, named `again` where they were so
    /// (skep #989), never those an earlier move's face named (skep #973), a
    /// refused run's face its first line's cause, the board's token, as the
    /// refused face is first said (skep #974), and names `landed`, the line
    /// the act kept, where it kept one (skep #968). `emit_said` touches the
    /// bus alone, so it is safe under the board's lock.
    fn say_as_told(&self, session: &SessionEntry, ph: &mut PrincipalHold, doc: &str, landed: Option<&LandedLine>) {
        let state = state_on(ph, doc);
        let moved = state == HeldState::Moved;
        let judged = if moved { ph.judged_on(doc) } else { None };
        let sendable = if moved && session.may_write() { ph.sendable_told(doc) } else { None };
        let told = if moved { self.told(session, doc).filter(|told| told.moved_for(judged.as_ref())) } else { None };
        let (hands, again) = told.map_or_else(|| (Vec::new(), false), |told| (told.hands, told.again));
        let face = MovedFace { hands: &hands, again, sendable, judged: judged.as_ref() };
        let cause = ph.queue.reasons_on(doc).next().map(|(_, reason)| reason.cause.clone()).filter(|_| state == HeldState::Refused);
        self.emit_said(session, doc, HeldSaid::of(ph.lines_on(doc), state, cause.as_deref(), face), landed);
    }

    /// Says the `held` event a moved face owes, its hands read first.
    ///
    /// A person's act, a landing, or a line entered or kept behind the line
    /// the verdict rides left `owed.doc` moved (skep #960, #972, #973, #974),
    /// and no face told `session` named the hands of the verdict it stands on
    /// ([`HandsOwed`]). It runs with no lock held. Where the board
    /// answers and the own node runs, the hands are read for the line the
    /// board's verdict rides, as every moved face's are
    /// ([`Holds::hands_since_typed_state`]); elsewhere no read is made,
    /// nothing more of the hold's dialed at a board not answering (§3c.5).
    /// The event is said under the board's lock again. Where that line stands
    /// at the head as it stood, it says the document `moved` with the hands
    /// read, named `again` where they were so (skep #989), and the verdict
    /// they were read for, its `sendable` and `landed` beside them — or, where
    /// no page named them, the read going unanswered, answered with no page,
    /// meeting the death signal or not made, with the hands not read
    /// ([`Hand::UNREAD`], SP-14), the document owing them to the walk
    /// ([`PrincipalHold::hands_owed`]) and a board that gave the read no
    /// answer marked unanswered, and where the board has reclaimed the
    /// history, with them `unknowable` ([`Hand::UNKNOWABLE`]), owed to no
    /// read. Where the document moved on while the read was out — a `send` of
    /// it, its head kept or dropped — it says what stands, the hands as told
    /// ([`Holds::say_as_told`]), save a document moved again under a new
    /// verdict that no face told `session` of, which names its hands not read
    /// for that verdict and owes them to the walk. The act's answer stands
    /// whatever the read met: a death at it is met again, and the session
    /// ended, at the next request its token is dialed with.
    fn say_with_hands(&self, session: &SessionEntry, owed: HandsOwed) {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let HandsOwed { doc, k, reason, landed } = owed;
        let dials = {
            let board_hold = self.lock(board_reference);
            board_hold.answers() && !board_hold.node_stopped
        };
        let read = dials.then(|| self.hands_since_typed_state(session, &doc, Some(k), &reason)).and_then(HandsRead::face).unwrap_or_else(HandsFace::not_read);
        let mut board_hold = self.lock(board_reference);
        if read.unanswered {
            self.note_unanswered(&mut board_hold, None);
        }
        let ph = board_hold.principals.get_mut(&principal).expect("the principal's hold, entered by its door");
        let (judged, read) = if ph.queue.reasons_on(&doc).next().is_some_and(|(head, standing)| head == k && *standing == reason) {
            (Judged::of(k, &reason), read)
        } else if let Some((head, standing)) = self.hands_owed_to(session, ph, &doc) {
            // Moved again while the read was out, under a verdict the read
            // was not made for.
            (Judged::of(head, &standing), HandsFace::not_read())
        } else {
            self.say_as_told(session, ph, &doc, landed.as_ref());
            return;
        };
        if let Some(judged) = judged.as_ref().filter(|_| read.hands.contains(&Hand::UNREAD)) {
            ph.hands_owed.insert(doc.clone(), judged.k);
        }
        let sendable = if session.may_write() { ph.sendable_told(&doc) } else { None };
        let face = MovedFace { hands: &read.hands, again: read.again, sendable, judged: judged.as_ref() };
        self.emit_said(session, &doc, HeldSaid::of(ph.lines_on(&doc), HeldState::Moved, None, face), landed.as_ref());
    }

    /// Says what stands on `doc` where a line ahead of `k` awaits an act.
    ///
    /// It answers whether it said it (§4b.2; skep #974), and runs with no
    /// lock held. Where the document's first line awaits the person's act
    /// ([`PrincipalHold::first_awaiting_act`]) and is not line `k`, what
    /// stands is said under the board's lock as a person's act says it
    /// ([`Holds::say_standing`]) — that line's state kept in front, the count
    /// counting every line behind it — naming `landed`, where a keep left the
    /// line first, and the event its hands owe is said once the lock is let
    /// go ([`Holds::say_with_hands`]). It says nothing otherwise, the caller
    /// then saying its own face.
    fn say_standing_ahead_of(&self, session: &SessionEntry, doc: &str, k: u64, landed: Option<&LandedLine>) -> bool {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let said = self.with_principal(board_reference, principal, |ph| ph.first_awaiting_act(doc).filter(|&first| first != k).map(|_| self.say_standing(session, ph, doc, landed)));
        let Some(owed) = said.flatten() else { return false };
        if let Some(owed) = owed {
            self.say_with_hands(session, owed);
        }
        true
    }

    /// Emits the `held` event an end of a first dial's shift owes its line.
    ///
    /// Line `k` of `doc` says `state` under `cause`, save where a line ahead
    /// of it awaits the person's act, whose state stays in front
    /// ([`Holds::say_standing_ahead_of`]; skep #974). It runs with no lock
    /// held, the line let go ([`LineOut`]), so an act its face asks for takes
    /// it ([`Holds::shift_at_first_dial`]).
    fn say_after_shift(&self, session: &SessionEntry, doc: &str, k: u64, state: HeldState, cause: &str) {
        if self.say_standing_ahead_of(session, doc, k, None) {
            return;
        }
        let lines = self.lines_on(&session.board_reference, session.facts.principal, doc);
        self.emit_held(session, doc, lines, state, Some(cause), MovedFace::default());
    }

    /// Emits the `held` event for a line the resend kept.
    ///
    /// It names `landed` (skep #968), `lines` standing on `doc` after it: the
    /// state `sending` where one stands, else `kept` — save where the line
    /// that stands first now awaits the person's act, whose state stays in
    /// front, the hands it owes read once the board's lock is let go
    /// ([`Holds::say_standing_ahead_of`]; skep #974). It is a resent line's
    /// ack and a head the resend's read found landed (`resend`'s `send_line`
    /// and `resume_doc`), said with no lock held.
    fn say_kept(&self, session: &SessionEntry, doc: &str, lines: LinesOn, landed: &LandedLine) {
        if self.say_standing_ahead_of(session, doc, landed.k, Some(landed)) {
            return;
        }
        let state = if lines.held == 0 { HeldState::Kept } else { HeldState::Sending };
        self.emit_said(session, doc, HeldSaid::of(lines, state, None, MovedFace::default()), Some(landed));
    }

    /// Marks owed the shift tests of the documents a drafts read named.
    ///
    /// `rows` are the documents a read of `principal`'s drafts feed named
    /// (§3c.5; skep #867): the shift test of each moved document among them
    /// goes stale, and the walk runs it again at the next probe, one read at
    /// most per document per pass. It dials nothing, so the feed thread's
    /// read waits on no board.
    ///
    /// # Panics
    ///
    /// Panics where `board_reference` names no board the holds were opened
    /// over (the type's precondition).
    pub(crate) fn note_rows(&self, board_reference: &str, principal: u64, rows: &RowsNamed) {
        if rows.is_empty() {
            return;
        }
        self.with_principal(board_reference, principal, |ph| {
            ph.shift_tests.iter_mut().filter(|(doc, _)| rows.names(doc)).for_each(|(_, test)| test.stale = true);
        });
    }

    /// Enters a current shift test of line `k` on `doc`, its document moved.
    ///
    /// It is the suites' seam where a feed is driven with no line held.
    #[cfg(test)]
    pub(crate) fn seed_shift_test(&self, session: &SessionEntry, doc: &str, k: u64) {
        self.with_principal(&session.board_reference, session.facts.principal, |ph| {
            ph.shift_tests.insert(doc.to_string(), ShiftTest { k, answer: Tested::Sendable(false), stale: false, told: false });
        });
    }

    /// Returns whether `doc`'s shift test stands stale, where one stands.
    ///
    /// It is the suites' seam beside [`Holds::seed_shift_test`].
    #[cfg(test)]
    pub(crate) fn shift_test_stale(&self, session: &SessionEntry, doc: &str) -> Option<bool> {
        self.with_principal(&session.board_reference, session.facts.principal, |ph| ph.shift_tests.get(doc).map(|test| test.stale)).flatten()
    }

    /// Notes and answers the `writes.halted` of the board's `/health`.
    ///
    /// The `/health` is as the feed's tick or the probe read it; its
    /// `writes.halted` (wire.md §The other endpoints) is noted — every burst
    /// holds `halted` from the first `true` to the next `false` (§3c.4) —
    /// and answered. A read that says writes go ends a `poisoned` state too:
    /// a poisoned board answers `writes.halted` true until its restart, so
    /// the first `false` after a `poisoned` answer is the restart's. The
    /// board answered, so its silence ends, and a request pending the verdict
    /// was its line's own ([`Holds::note_answering`]).
    pub fn note_health(&self, board_reference: &str, health: &Health) -> bool {
        let writes_halted = health.body["writes"]["halted"].as_bool().unwrap_or(false);
        let mut board_hold = self.lock(board_reference);
        self.note_answering(&mut board_hold);
        board_hold.writes_halted = writes_halted;
        if !writes_halted {
            board_hold.poisoned = false;
        }
        writes_halted
    }

    /// Notes one `/health` read of the board, and answers its verdict.
    ///
    /// It is §3c.4's THE END.
    ///
    /// The read is the probe's, the feed thread's — at its start, its tick,
    /// the commit stream's failure — or the page's, `probe()`'s or
    /// `health(board)`'s. One the board gave no answer to
    /// (`DialError::unanswered`) is its silence ([`Holds::note_silence`]);
    /// one refused before any connection opened notes nothing
    /// ([`Verdict::Undialed`]); any answer is the board answering — a
    /// document read for its `writes.halted` ([`Holds::note_health`]), a
    /// refusal or bytes no `/health` reads ([`Holds::note_answering`]).
    ///
    /// # Panics
    ///
    /// Panics where `board_reference` names no board the holds were opened
    /// over (the type's precondition).
    pub fn note_health_read(&self, board_reference: &str, read: &Result<Health, Halt>) -> Verdict {
        match read {
            Ok(health) if self.note_health(board_reference, health) => Verdict::Holds,
            Ok(_) => Verdict::Writes,
            Err(h) if unanswered(h) => {
                self.note_silence(&mut self.lock(board_reference));
                Verdict::Silent
            }
            Err(Halt::Dial(e)) if !e.answered() => Verdict::Undialed,
            Err(_) => {
                self.note_answering(&mut self.lock(board_reference));
                Verdict::Holds
            }
        }
    }

    /// Returns whether the board's last `/health` verdict was silence (§3c.4).
    ///
    /// A request of the hold's the board gave no answer to, its verdict
    /// pending, is no silence yet. It is the suites' seam where a stop
    /// outranks the silence in the board's state.
    #[cfg(test)]
    pub(crate) fn silent(&self, board_reference: &str) -> bool {
        self.lock(board_reference).silent()
    }

    /// Returns the board's state as it stands (§4b.2; P37; skep #865).
    ///
    /// It is what `probe()` answers, read after its own `/health` note.
    ///
    /// # Panics
    ///
    /// Panics where `board_reference` names no board the holds were opened
    /// over (the type's precondition).
    pub fn state(&self, board_reference: &str) -> BoardState {
        self.lock(board_reference).state()
    }

    /// Takes the change of the board's state since it was last told, if any.
    ///
    /// The change is taken under the board's lock, so each is answered once
    /// and a steady state answers none (§4b.2; P37; SP-11; skep #865). Its
    /// one reader is the board's feed thread (`Feeder::announce`), which says
    /// it on the `daemon` event. A state keeps its one telling whatever its
    /// cause reads as since: only another state is a change.
    ///
    /// # Panics
    ///
    /// Panics where `board_reference` names no board the holds were opened
    /// over (the type's precondition).
    pub fn state_change(&self, board_reference: &str) -> Option<BoardEdge> {
        let mut board_hold = self.lock(board_reference);
        let to = board_hold.state();
        if to.as_str() == board_hold.told.as_str() {
            return None;
        }
        let from = std::mem::replace(&mut board_hold.told, to.clone());
        Some(BoardEdge { from, to })
    }

    /// Reads the board term a signed write under `session` signs over.
    ///
    /// It is `SessionEntry::signing_term`'s read, noted as every read of the
    /// board's head is ([`Holds::note_head`]; skep #865): the one way a
    /// write reads its head, and the way a read of an account's labels reads
    /// the term its records' frames were signed over (`labels`).
    pub(crate) fn signing_term(&self, session: &SessionEntry) -> HeadRead {
        let head = session.signing_term();
        self.note_head(&session.board_reference, &head);
        head
    }

    /// Returns the frame a send under `session` dials ([`AttestedWhereOwed`]).
    ///
    /// Its attest is composed now where one is owed.
    ///
    /// # Errors
    ///
    /// Returns why none could be composed, nothing dialed, which the send
    /// answers as `Dialed`'s `From<Unattested>` reads it.
    fn attest_where_owed<'f>(&self, session: &SessionEntry, frame: &'f Value) -> Result<AttestedWhereOwed<'f>, Unattested> {
        Ok(AttestedWhereOwed(session.attest(&self.key_store, frame, || self.signing_term(session))?))
    }

    /// Dials an [`AttestedWhereOwed`] frame once under `session`.
    ///
    /// The dial goes to the board the session stands at, its answer read
    /// once through [`classify`], `given` the reissues this write has been
    /// given. A non-200 is read by its code, so `write_busy`'s 503 meets its
    /// row. A `poisoned` answer is noted at the board's hold: the
    /// unholdable writes are refused `poisoned` from it until a `/health`
    /// read says writes go ([`BoardHold::poisoned`]).
    fn dial(&self, session: &SessionEntry, frame: &AttestedWhereOwed<'_>, given: &Reissues) -> Dialed {
        let dialed = match session.board.op(Some(&session.token), &frame.0) {
            Ok(Answer::Closed) => Dialed::Died,
            Ok(Answer::Document(v)) => match Rejection::of(&v) {
                None => Dialed::Acked(v),
                Some(r) => {
                    let decision = classify(DialOutcome::Rejected { code: r.key(), disposition: v["disposition"].as_str().unwrap_or("") }, given);
                    let refusal = Refusal::from(r.refused(&v));
                    Dialed::refused(decision, &r.token(), v, refusal)
                }
            },
            Err(Halt::Dial(e)) => match classify(DialOutcome::Dial(&e), given) {
                Decision::Unanswered { sent } => Dialed::unanswered(sent, Refusal::Unreachable(e)),
                Decision::Hold { cause, sent } => Dialed::Held { reason: Reason::of(cause, sent), refusal: Refusal::Unreachable(e) },
                _ => Dialed::Faced(Refusal::Unreachable(e)),
            },
            Err(Halt::Refused(r)) => {
                let decision = classify(DialOutcome::Rejected { code: &r.code, disposition: r.body["disposition"].as_str().unwrap_or("") }, given);
                // A refused run's line keeps the verdict, and the refusal the
                // body it was read from: two owners, one copy.
                let (token, verdict) = (r.token(), r.body.clone());
                Dialed::refused(decision, &token, verdict, Refusal::Board(r))
            }
            Err(h) => Dialed::Faced(Refusal::from(h)),
        };
        if matches!(&dialed, Dialed::Held { reason, .. } if reason.cause == cause::POISONED) {
            self.lock(&session.board_reference).poisoned = true;
        }
        dialed
    }

    /// Re-marks one line of `principal`'s in place, its ordinal kept.
    ///
    /// It serves a hold that recurs, a refused run, a moved re-facing and the
    /// mark a resend writes before its dial; the queue takes the reason
    /// whatever the disk did. A copy the device refuses is owed, and the wait
    /// it begins is said at its edges ([`Holds::note_waiting`]); a copy the
    /// writer refuses, past the file's re-mark budget or its line bound, is
    /// owed never, and said on `Talk` as it is refused
    /// ([`Holds::say_remarks_refused`]).
    fn remark_line(&self, principal: u64, ph: &mut PrincipalHold, k: u64, reason: Reason) {
        if let Err(e) = ph.queue.remark(k, reason) {
            self.say_remarks_refused(&[(k, e)]);
        }
        self.note_waiting(principal, ph);
    }

    /// Readies a line for a resend's dial, and returns its dial id.
    ///
    /// It is line `k` of `principal`'s (skep #971). The line names its dial id
    /// where it names none, and is marked as one
    /// that may have landed, as one copy (`HeldQueue::ready_to_resend`): a
    /// copy the device refuses is owed, and the wait it begins is said at its
    /// edges ([`Holds::note_waiting`]); one the writer refuses is owed never,
    /// and said on `Talk` ([`Holds::say_remarks_refused`]). It answers none
    /// where no line of `k` stands.
    fn ready_to_resend(&self, principal: u64, ph: &mut PrincipalHold, k: u64) -> Option<DialId> {
        let (dial_id, refused) = ph.queue.ready_to_resend(k)?;
        if let Some(e) = refused {
            self.say_remarks_refused(&[(k, e)]);
        }
        self.note_waiting(principal, ph);
        Some(dial_id)
    }

    /// Re-marks a run of `principal`'s lines in place, as one copy.
    ///
    /// It serves a moved document's marks (`resend`'s `mark_moved`) and the
    /// person's `send` on a document ([`Holds::resolve`]), each `base` raised
    /// to `raise` where it names one (skep #861): each line of `marks` takes
    /// its reason in the queue whatever the disk did, and the run's copies go
    /// to the held file as one copy with one sync (`HeldQueue::remark_all`).
    /// A copy the device refuses is owed, and the wait it begins is said at
    /// its edges, once for the run ([`Holds::note_waiting`]); the copies the
    /// writer refuses are owed never, and said on `Talk` in one line however
    /// many they are ([`Holds::say_remarks_refused`]).
    fn remark_lines(&self, principal: u64, ph: &mut PrincipalHold, marks: impl IntoIterator<Item = (u64, Reason)>, raise: Option<u64>) {
        let refused = ph.queue.remark_all(marks, raise);
        self.say_remarks_refused(&refused);
        self.note_waiting(principal, ph);
    }

    /// Says the re-marks the writer refused, in one line (SP-11).
    ///
    /// Each was refused before any I/O — past the file's re-mark budget, or
    /// its line past the line bound — and is owed never, so a reopen reads
    /// its line's earlier copy. One is said by its line; several by their
    /// count, the first's line and its refusal, so a run past a spent budget
    /// says one line however many of its re-marks the writer refuses.
    fn say_remarks_refused(&self, refused: &[(u64, io::Error)]) {
        match refused {
            [] => {}
            [(k, e)] => self.say(format_args!("line {k}'s re-mark could not be written ({e}); a reopen reads its earlier one")),
            [(k, e), ..] => self.say(format_args!("{} lines' re-marks could not be written, line {k}'s the first ({e}); a reopen reads each line's earlier one", refused.len())),
        }
    }

    /// Takes one line of `principal`'s out of the queue, whatever the disk
    /// did.
    ///
    /// A `done` the device refuses is owed, and the wait it begins is said at
    /// its edges; a held file the volume would not remove once every line in
    /// it was settled is said on `Talk` — the store appends on to it — and
    /// the line's reissues and the position its moved document was
    /// acknowledged through go with it ([`Holds::forget_settled`]). The lines
    /// whose anchors named its words keep anchors no more, no address of the
    /// words known (skep #969).
    fn done_line(&self, principal: u64, ph: &mut PrincipalHold, k: u64, done: Done) {
        let settled = ph.queue.done(k, done).unwrap_or_default();
        self.forget_settled(principal, ph, &[k], settled);
    }

    /// Keeps one line of `principal`'s at `at`, whatever the disk did.
    ///
    /// It is [`Holds::done_line`]'s keep, `minted` the first I-address a
    /// kept insert's words were minted at where its ack or the resend's
    /// read names one ([`minted_by`], `resend`'s `minted_at`): the pieces
    /// later lines' anchors name of its words are placed there, its `done`
    /// carrying the address (`HeldQueue::keep`), and where it names none the
    /// lines naming them keep anchors no more (skep #969).
    fn keep_line(&self, principal: u64, ph: &mut PrincipalHold, k: u64, at: Option<u64>, minted: Option<&str>) {
        let settled = ph.queue.keep(k, at, minted).unwrap_or_default();
        self.forget_settled(principal, ph, &[k], settled);
    }

    /// Takes a run of `principal`'s lines out of the queue, as one copy.
    ///
    /// It serves the drop ([`Holds::drop_run`]; skep #861): every line of
    /// `ks` leaves the queue whatever the disk did, the run's `done`s go to
    /// the held file as one copy with one sync (`HeldQueue::done_all`), and
    /// what the settle did is said once for the run, as one line's is
    /// ([`Holds::forget_settled`]).
    fn done_lines(&self, principal: u64, ph: &mut PrincipalHold, ks: &[u64], done: Done) {
        let settled = ph.queue.done_all(ks, done);
        self.forget_settled(principal, ph, ks, settled);
    }

    /// Forgets the lines `ks` once settled, and says what the settle did.
    ///
    /// Each line's reissues, the position its moved document was
    /// acknowledged through, its untried shift, its unread hands, its shift
    /// test and its place among the lines no dial of which left go; a
    /// held file the volume would not remove once every line in it was
    /// settled is said on `Talk` — the store appends on to it — and a wait
    /// for the file's copies that begins or ends is said at its edges
    /// ([`Holds::note_waiting`]). The standing lines whose anchors named the
    /// words of a line settled with no address of them known, and keep
    /// anchors no more, are said once, as the settle drops them (SP-11; skep
    /// #969): such a line the board refuses as typed against an older state
    /// is held as moved, no shift able to place it.
    fn forget_settled(&self, principal: u64, ph: &mut PrincipalHold, ks: &[u64], settled: Settled) {
        if let Some((path, e)) = settled.unremoved {
            self.say(format_args!("every held line is done, and the held file {} could not be removed ({e}); it stands, and the next line is appended to it", path.display()));
        }
        if !settled.unplaced.is_empty() {
            let ordinals = |ks: &[u64]| ks.iter().map(u64::to_string).collect::<Vec<_>>().join(", ");
            self.say(format_args!(
                "held line(s) {} named words of line(s) {} that left the queue with no address of them known; their anchors are dropped, and a send of them the board refuses as typed against an older state is held as moved",
                ordinals(&settled.unplaced),
                ordinals(ks)
            ));
        }
        for k in ks {
            ph.reissues.remove(k);
            ph.seen_through.remove(k);
            ph.shift_owed.remove(k);
            ph.never_left.remove(k);
        }
        ph.hands_owed.retain(|_, judged| !ks.contains(judged));
        ph.shift_tests.retain(|_, test| !ks.contains(&test.k));
        self.note_waiting(principal, ph);
    }

    /// Says the edges of a principal's wait for its held file's copies.
    ///
    /// The wait (§3c.3; skep #813, #821) is the copies the queue's file owes:
    /// a line's first copy, refused, and every line held after it, each in
    /// memory alone; and a re-mark, a raise, a shift or a `done` the device
    /// refused for a line on disk, which the file holds as it last copied it —
    /// all written in `k` order by the retry (`HeldQueue::retry`). It is said
    /// in the shell's own window, as SP-11 and SP-12 have it: once as it
    /// begins — the copy the retry stopped at, its refusal, that a close
    /// before the retry lands loses every copy owed, and that a relaunch reads
    /// each line as the file last held it — and once as nothing is owed,
    /// whether the retry wrote the copies or their lines left the queue; never
    /// at each refused retry. The page reads the same refusal in every waiting
    /// line's `unwritable`.
    fn note_waiting(&self, principal: u64, ph: &mut PrincipalHold) {
        match (ph.queue.waiting(), ph.waiting_said) {
            (Some(waiting), false) => {
                let k = waiting.first();
                let copy = match waiting.owed() {
                    Owed::Line => format!("held line {k}"),
                    Owed::Mark => format!("held line {k}'s re-mark"),
                    Owed::Done => format!("held line {k}'s `done`"),
                };
                self.say(format_args!(
                    "principal {principal}'s {copy} could not be copied to its held file ({}); it and every copy owed after it wait in memory, written in order as soon as the device takes them, and a close before then loses them: a relaunch reads each line as the file last held it",
                    waiting.refusal()
                ));
                ph.waiting_said = true;
            }
            (None, true) => {
                self.say(format_args!("principal {principal}'s held lines wait in memory no more: its held file holds every line as the queue does"));
                ph.waiting_said = false;
            }
            (Some(_), true) | (None, false) => {}
        }
        // The pending file the queue's file took its lines from, standing
        // past a refused removal: said once, and once as it goes (SP-11).
        match (ph.queue.superseded(), ph.superseded_said) {
            (Some((path, Some(e))), false) => {
                self.say(format_args!("principal {principal}'s pending held file {} was joined and could not be removed ({e}); it stands, tried again at each copy and each probe, and its lines are joined no second time", path.display()));
                ph.superseded_said = true;
            }
            (None, true) => {
                self.say(format_args!("principal {principal}'s pending held file is removed now"));
                ph.superseded_said = false;
            }
            _ => {}
        }
    }

    /// Emits the `held` event (§4b.2), naming no line kept.
    ///
    /// It says `lines`, `state`, `cause` and `face` of `doc` at the session's
    /// board, as [`Holds::emit_said`] says every `held` event.
    fn emit_held(&self, session: &SessionEntry, doc: &str, lines: LinesOn, state: HeldState, cause: Option<&str>, face: MovedFace<'_>) {
        self.emit_said(session, doc, HeldSaid::of(lines, state, cause, face), None);
    }

    /// Emits the `held` event (§4b.2) that says `said` of `doc`.
    ///
    /// It goes out once per change of the document's state, and at every
    /// line kept.
    ///
    /// It is `{board, session, doc, held, state, cause?, hands?, again?,
    /// sendable?, unwritable?, unwritable_class?, landed?}`, under the session
    /// the change was made for — `hands` with the `moved` state alone, the
    /// hands whose rows moved the document (§3c.5), each once, or the one hand
    /// `unread` where the board gave their read no answer, or `unknowable`
    /// where it has reclaimed the history the read asks for; `again`, true,
    /// beside hands a burst refused again with no row since the person's
    /// `send` names again (skep #989); `sendable` with that state alone,
    /// where the shell knows what a `send` would do ([`Tested`]; skep #867);
    /// the two members together while a line of the document has no copy on
    /// disk ([`Unwritable`]; skep #860); and `landed` where `landed` names the
    /// line just kept, its one entry — a resent line's ack, a head the
    /// resend's read found landed, a drop's read that found its line landed
    /// (skep #968). An emit that repeats what was last emitted for the same
    /// board, session and document is none ([`HeldSaid::repeated_by`]; skep
    /// #727): a document's state is said as it changes, never again per
    /// probe; the first emit for a key is always made, a `moved` face for
    /// another verdict than the one remembered is made (skep #973), one naming
    /// a line kept is made whatever was last told, its pair the one remembered
    /// from it, and a document kept with no line left clears its key
    /// ([`Holds::last_emitted`]). The memory's lock is a leaf, taken here and
    /// released before the bus is reached, so the emit is safe under the
    /// board's lock as it is without one.
    fn emit_said(&self, session: &SessionEntry, doc: &str, said: HeldSaid, landed: Option<&LandedLine>) {
        let mut data = json!({"board": session.board_reference, "session": session.reference, "doc": doc, "held": said.held, "state": said.state.as_str()});
        if let Some(c) = &said.cause {
            data["cause"] = Value::from(c.as_str());
        }
        if !said.hands.is_empty() {
            data["hands"] = Value::Array(said.hands.iter().map(Hand::json).collect());
        }
        if said.again {
            data["again"] = Value::from(true);
        }
        if let Some(sendable) = said.sendable {
            data["sendable"] = Value::from(sendable);
        }
        if let Some(why) = &said.unwritable {
            why.answer_in(&mut data);
        }
        if let Some(landed) = landed {
            data["landed"] = json!([landed.json()]);
        }
        {
            let key = (session.board_reference.clone(), session.reference.clone(), doc.to_string());
            let mut last = self.last_emitted.lock().expect("the held events' memory");
            if landed.is_none() && last.get(&key).is_some_and(|told| told.repeated_by(&said)) {
                return;
            }
            if said.state == HeldState::Kept && said.held == 0 {
                last.remove(&key);
            } else {
                last.insert(key, said);
            }
        }
        self.bus.emit(EventName::Held, data);
    }

    /// Returns what the `held` event last told `session` of `doc`, if any.
    fn told(&self, session: &SessionEntry, doc: &str) -> Option<HeldSaid> {
        let key = (session.board_reference.clone(), session.reference.clone(), doc.to_string());
        self.last_emitted.lock().expect("the held events' memory").get(&key).cloned()
    }

    /// Returns the hands whose rows moved a document past a burst's state.
    ///
    /// The state is the burst's typed state (§3c.5; §4b.2's `held` event).
    ///
    /// `reason` is the line's as a dial held it, and `k` the line's ordinal
    /// where it has one — none for a first dial's hold, whose line is
    /// entered after the read. Where `reason` is `moved` with the board's
    /// verdict — the burst refused `arrangement_moved` — the rows are read
    /// since the later of the typed state the verdict echoes
    /// (`site.as_of`) and the position the person's last `send` on the
    /// document acknowledged the rows through, where one stands for line `k`
    /// ([`PrincipalHold::seen_through`], §3c.4):
    /// `GET /changes?since=<since>&under=<doc>&drafts=true` under the
    /// session, the rows that moved the document past the burst and that the
    /// person has not acknowledged, their hands named each once
    /// ([`Holds::hands_of`]). So a document moved again after the person's
    /// `send` names the hands since it alone, and a first moved face names
    /// every hand since the typed state, whatever the line's `base`, which
    /// can stand past the typed state for reasons of its own. Where that page
    /// names no row and the `send` stands, the board refusing the burst again
    /// for the change the person acknowledged, the rows are read again from
    /// where the face that `send` acknowledged read them
    /// ([`PrincipalHold::acknowledged`]), and the hands they name are named
    /// `again` (skep #989): a burst refused again is never told no one moved
    /// it. The acknowledgment is the shell's memory, as a line's clock is: a
    /// relaunch forgets it, and the first face after one names every hand
    /// since the typed state, not `again`, the line's raised `base`
    /// persisting. A page past the board's budget is asked again at the limit
    /// that fits, as the resend's read asks it; a page whose `more` stands
    /// names the hands of the page it holds, the rows past it unread. A read
    /// the board answers `history_reclaimed`, its floor past the read's
    /// position, is [`HandsRead::Unknowable`] (skep #989): the floor never
    /// moves down, so the moved face names its hands `unknowable` and no read
    /// is owed. A read the board answers with any other answer that is no
    /// page — a refusal, an answer no read takes — is [`HandsRead::Unread`]
    /// (skep #972): the moved face names its hands not read, read again as
    /// the walk meets the document. A read the board gives no answer to is
    /// [`HandsRead::Unanswered`] (skep #863): the moved face stands on the
    /// verdict, its hands named not read, apart from hands lost. The death
    /// signal on the session's token is no such answer: it is
    /// [`HandsRead::Died`], the session's death and no verdict on the
    /// document, which each caller meets as the death at its dial — the burst
    /// held for the session that stands next, and nothing faced moved
    /// (§3c.4). The second read answers as the first does. Any other reason
    /// reads nothing and names none.
    fn hands_since_typed_state(&self, session: &SessionEntry, doc: &str, k: Option<u64>, reason: &Reason) -> HandsRead {
        let Some(typed) = typed_state(reason) else { return HandsRead::Named { hands: Vec::new(), again: false } };
        // The rows the person's `send` acknowledged are named no more, save
        // where none has landed since.
        let seen = k.and_then(|k| self.with_principal(&session.board_reference, session.facts.principal, |ph| ph.seen_through.get(&k).copied()).flatten());
        let since = seen.map_or(typed, |seen| seen.through.max(typed));
        match (self.read_hands(session, doc, since), seen.filter(|seen| seen.from < since)) {
            (HandsRead::Named { hands, .. }, Some(seen)) if hands.is_empty() => match self.read_hands(session, doc, seen.from) {
                HandsRead::Named { hands, .. } => HandsRead::Named { again: !hands.is_empty(), hands },
                read => read,
            },
            (read, _) => read,
        }
    }

    /// Reads the hands of the rows under `doc` past `since`, one page.
    ///
    /// It is [`Holds::hands_since_typed_state`]'s one read: the page, re-asked
    /// at the limit that fits, its hands named each once ([`Holds::hands_of`])
    /// and never `again`; a reclaimed history, [`HandsRead::Unknowable`]; the
    /// death signal, [`HandsRead::Died`]; no answer, [`HandsRead::Unanswered`];
    /// any other answer, [`HandsRead::Unread`].
    fn read_hands(&self, session: &SessionEntry, doc: &str, since: u64) -> HandsRead {
        let mut query = ChangesQuery { since, under: Some(doc), drafts: true, limit: None };
        loop {
            match session.board.changes(Some(&session.token), &query) {
                Ok(ChangesAnswer::Page(page)) => return HandsRead::Named { hands: self.hands_of(session, &page.changes), again: false },
                // The client refuses a `fits` that does not shrink the page,
                // so the asks end.
                Ok(ChangesAnswer::TooLarge { fits }) => query.limit = Some(fits),
                Ok(ChangesAnswer::HistoryReclaimed { .. }) => return HandsRead::Unknowable,
                Ok(ChangesAnswer::Closed) => return HandsRead::Died,
                Err(h) if unanswered(&h) => return HandsRead::Unanswered,
                Ok(_) | Err(_) => return HandsRead::Unread,
            }
        }
    }

    /// Returns the hands of `rows`, each once (§3c.5; §4b.2).
    ///
    /// The rows are the `/changes` rows since a burst's typed state the
    /// board's verdict names ([`Holds::hands_since_typed_state`]).
    ///
    /// A row is this store's `own` where its `key` is the session's
    /// fingerprint, or where it is a signed entry — `attest` in place of
    /// `key`, the form the daemon keeps for a publish-class write alone
    /// (wire.md §`/changes`), which the resend's own-row test reads as the
    /// session's (`resend::own_row`); `bare` where its `key` says so;
    /// `lost` where its testimony is the reserved null; and `other` for any
    /// other key, its fingerprint carried and its label rendered inert: the
    /// one this shell's key store holds for it where the store holds that
    /// key, else the one the account's verified records give it
    /// ([`Holds::recorded_label`], whose read's cost `labels`' module doc
    /// states, SP-23), and none where neither names it. A store that cannot
    /// be listed gives no label of its own, said on `Talk` once per read
    /// (SP-12, SP-14), its keys looked up as keys it does not hold.
    fn hands_of(&self, session: &SessionEntry, rows: &[Value]) -> Vec<Hand> {
        let own_fingerprint = session.key().map(|key| key.to_hex());
        let mut labels: Option<Vec<KeyFacts>> = None;
        let mut read_made = false;
        let mut hands: Vec<Hand> = Vec::new();
        for row in rows {
            let hand = if row["docs"].is_null() && row["key"].is_null() && row["op"].is_null() {
                Hand { key: "lost", fingerprint: None, label: None }
            } else {
                match row["key"].as_str() {
                    Some("bare") => Hand { key: "bare", fingerprint: None, label: None },
                    Some(key) if Some(key) == own_fingerprint.as_deref() => Hand { key: "own", fingerprint: Some(key.to_string()), label: None },
                    Some(key) => {
                        let keys = labels.get_or_insert_with(|| match self.key_store.list() {
                            Ok(keys) => keys,
                            Err(e) => {
                                self.say(format_args!("the key store could not be listed to label another hand's key ({e}); the hand takes no label of this store's"));
                                Vec::new()
                            }
                        });
                        let label = match keys.iter().find(|k| k.fingerprint.to_hex() == key) {
                            Some(held) => held.label.as_deref().map(render_inert),
                            None => self.recorded_label(session, key, row["at"].as_u64(), keys, &mut read_made),
                        };
                        Hand { key: "other", fingerprint: Some(key.to_string()), label }
                    }
                    None if row.get("attest").is_some() => Hand { key: "own", fingerprint: own_fingerprint.clone(), label: None },
                    None => Hand { key: "other", fingerprint: None, label: None },
                }
            };
            if !hands.contains(&hand) {
                hands.push(hand);
            }
        }
        hands
    }
}

/// Returns the refusal for what the queue refused (`held::Unheld`).
///
/// It is the principal's queue full — its frames' and anchors' bytes, its
/// lines or its ordinals — its detail naming the bytes held, the burst's
/// frame's and its anchors' against `cap`, and the lines held against
/// `line_cap`; or — never for a burst [`Burst::admit`] let in — a line no
/// reader of the file reads.
fn queue_refused(why: Unheld) -> Refusal {
    match why {
        Unheld::Full { held_bytes, frame_bytes, anchor_bytes, held_lines } => Refusal::shell(
            Name::HELD_FULL,
            json!({"held_bytes": held_bytes, "frame_bytes": frame_bytes, "anchor_bytes": anchor_bytes, "cap": MAX_HELD_BYTES, "held_lines": held_lines, "line_cap": MAX_HELD_LINES}),
        ),
        Unheld::Unreadable => Refusal::malformed("frame.doc"),
    }
}

/// Returns P38's halt face for `held(session)` and every act (§3c.3).
///
/// Its detail is the `why` alone, no path crossing the bridge (§4b.3;
/// SP-15): the native side reads the file ([`Holds::halted_file`]), and the
/// page asks for its showing ([`Holds::show_halted`]).
fn store_halted(why: HaltWhy) -> Refusal {
    Refusal::shell(Name::STORE_HALTED, json!({"why": why.token()}))
}

/// Returns line `k` of `ph`'s queue where the person's `act` may take it.
///
/// It is `resolve`'s check of the line (P10). No act takes a line a send has
/// out for its dials ([`PrincipalHold::dialing`]; skep #983): its answer
/// acts on the line. Else the drop takes every line, under any session —
/// a refused run's, a moved document's, and a holding one, the person's
/// discard of words the board may never have had (skep #726, #896, #983) —
/// and the send a line awaiting the person's act alone.
///
/// # Errors
///
/// Returns `no_such_held` where no line of ordinal `k` stands, then
/// `not_resolvable` where a send has the line out, or the act is a `send`
/// of a line that awaits no act of the person's.
fn resolvable(ph: &PrincipalHold, k: u64, act: ResolveAct) -> Result<HeldLine, Refusal> {
    let Some(line) = ph.queue.line(k) else { return Err(Refusal::shell(Name::NO_SUCH_HELD, json!({"held": k}))) };
    let takes = match act {
        ResolveAct::Drop => true,
        ResolveAct::Send => awaits_act(&line.reason),
    };
    if ph.dialing.contains(&k) || !takes {
        return Err(Refusal::shell(Name::NOT_RESOLVABLE, json!({"held": k})));
    }
    Ok(line)
}

/// Returns whether `act` on `line` reads for the line's landing first.
///
/// It does for the drop, under a session that may write, of a line that may
/// have landed ([`PrincipalHold::may_have_landed`]) and is holding or was
/// handed over as `answers_lost`: the board may hold its words (§3c.4,
/// §3c.5; skep #866, #983). A refused run's or a moved document's other
/// drops are the face's own discard, at once; the keyless session's rows are
/// never its own, so no read of its finds the line's landing, and its discard
/// reads for none. Each of those names the lines it takes that may have
/// landed in its answer instead ([`Holds::drop_run`]; skep #993).
fn reads_first(ph: &PrincipalHold, line: &HeldLine, act: ResolveAct, session: &SessionEntry) -> bool {
    let read_for = line_state(&line.reason) == HeldState::Holding || line.reason.cause == Name::ANSWERS_LOST.as_str();
    act == ResolveAct::Drop && session.may_write() && read_for && ph.may_have_landed(line.k, &line.reason)
}

/// Returns the refusal of a drop that cannot tell whether line `k` landed.
///
/// It is `landing_unread {held, why}` (§3c.4; skep #866): nothing dropped.
fn landing_unread(k: u64, why: LandingUnread) -> Refusal {
    Refusal::shell(Name::LANDING_UNREAD, json!({"held": k, "why": why.as_str()}))
}

/// Returns the state `doc` stands in, as the `held` event says it.
///
/// It is the state of the line that stands first in `ph`'s queue — a moved
/// line held before a dropped one keeps the document `moved` — or `kept`
/// where no line stands.
fn state_on(ph: &PrincipalHold, doc: &str) -> HeldState {
    ph.queue.reasons_on(doc).next().map_or(HeldState::Kept, |(_, reason)| line_state(reason))
}

/// Returns the line showing a halted held file in the shell's own window.
///
/// It names the file, why it is halted, and the act its why asks (§3c.3):
/// a file a newer skep wrote, or one whose header this skep does not read,
/// is opened by the skep that wrote it; a damaged one no skep reads whole,
/// so it is moved aside. Either way the bursts it holds go with the file,
/// unsent.
fn halted_line(principal: u64, path: &Path, why: HaltWhy) -> String {
    let open_with_the_writer = "open it with the skep that wrote it, or, with this shell stopped, move the file aside";
    let (cause, act) = match why {
        HaltWhy::Newer => ("written by a newer skep", open_with_the_writer),
        HaltWhy::UnknownMember => ("its header is not one this skep reads", open_with_the_writer),
        HaltWhy::Damaged => ("damaged: a line of it is not one this skep reads whole", "no skep reads it whole: with this shell stopped, move the file aside, and the next open begins a fresh one"),
    };
    format!(
        "principal {principal}'s held file {} is halted ({cause}): every burst of the principal's at this board is refused `store_halted`, and the file is left as found — {act}; the bursts it holds go with it, unsent",
        path.display()
    )
}

/// Returns the words the shell's own window names `dir`'s files by after a
/// principal's: `held file` in a board's own directory, `pending held file`
/// in the pending one.
fn file_word(dir: &HeldDir) -> &'static str {
    if dir.is_pending() {
        "pending held file"
    } else {
        "held file"
    }
}

/// Returns the words the shell's own window names the file a join enters
/// lines into: the board's held file, or the pending one.
fn the_file(dir: &HeldDir) -> &'static str {
    if dir.is_pending() {
        "the pending held file"
    } else {
        "the board's held file"
    }
}

/// Returns the refusal a burst meets where another shell holds the board's
/// store: `another_window` naming its op, as the shell's write door names
/// it (§3c.3; skep #828); `None` where the store is not another shell's.
///
/// It is the hold's own door behind the shell's: a burst that passed the
/// write door before the state was found — a probe's try of the locks
/// between the door and the hold — is refused as the door refuses one,
/// nothing held and nothing sent, so a shell that finds either lock held
/// writes nothing.
fn another_window(board_hold: &BoardHold, burst: &Burst) -> Option<Refusal> {
    matches!(board_hold.directory, Directory::AnotherWindow { .. }).then(|| Refusal::shell(Name::ANOTHER_WINDOW, json!({"op": burst.frame()["op"].as_str().unwrap_or("")})))
}

/// Returns the cause said of a principal's file whose read was refused.
///
/// It is one cause for the door's open and the pending → chain change
/// alike, so the refusal is said once whichever meets it first
/// ([`Holds::say_kept_from_file`]).
fn unread_cause(principal: u64, dir: &HeldDir, e: &io::Error) -> String {
    format!("principal {principal}'s {} could not be read ({e})", file_word(dir))
}

/// Returns the cause said of a file whose renumbering was refused.
///
/// The renumbering is [`PrincipalHold::renumbers`]'s (`HeldQueue::renumber`).
/// It is one cause for the door's open and the pending → chain change
/// alike, as [`unread_cause`] is, so the refusal is said once whichever
/// meets it first.
fn unrenumbered_cause(principal: u64, dir: &HeldDir, refused: &RenumberRefused) -> String {
    format!(
        "principal {principal}'s {} holds lines an earlier run left under ordinals this run has reached, and they could not be renumbered past this run's (line {}: {})",
        file_word(dir),
        refused.k,
        refused.error
    )
}

/// Returns one held line as `held(session)` lists it (§4b.1).
///
/// It holds the line's members save `id`, `anchors` beside a line whose
/// burst carried them, `refusal` beside a refused run's or a moved line's,
/// `sendable` beside a moved document's first moved line, where the shell
/// knows what a `send` would do ([`PrincipalHold::sendable_of`]), the `hands`
/// of `face` — its document's moved face — and `again` where they are named
/// so, beside each moved line of a moved document, where they name any, as
/// the `held` event spells them ([`Hand`]; skep #973, #989), and
/// `unwritable` and `unwritable_class` beside a line with no copy on disk
/// (§3c.3; skep #860).
fn line_json(l: &HeldLine, sendable: Option<bool>, face: Option<&HeldSaid>, unwritable: Option<&Unwritable>) -> Value {
    let mut line = json!({"held": l.k, "doc": l.doc, "base": l.base, "frame": l.frame, "cause": l.reason.cause, "sent": l.reason.sent, "time": l.time});
    if let Some(anchors) = &l.anchors {
        line["anchors"] = anchors.json();
    }
    if let Some(r) = &l.reason.refusal {
        line["refusal"] = r.clone();
    }
    if let Some(sendable) = sendable {
        line["sendable"] = Value::from(sendable);
    }
    if let Some(face) = face.filter(|face| !face.hands.is_empty()) {
        line["hands"] = Value::Array(face.hands.iter().map(Hand::json).collect());
        if face.again {
            line["again"] = Value::from(true);
        }
    }
    if let Some(why) = unwritable {
        why.answer_in(&mut line);
    }
    line
}

/// Returns the document an arrangement write re-arranges: the `doc` of one
/// of the five bursts or of a `set_arrangement` (wire.md §Arrangement, the
/// typed state); `None` for any other write.
fn arranged_doc(frame: &Value) -> Option<&str> {
    let op = frame["op"].as_str()?;
    (BURST_KINDS.contains(&op) || op == "set_arrangement").then(|| frame["doc"].as_str()).flatten()
}

/// Returns the first I-address an insert's ack minted its words at.
///
/// It is [`minted_on`] the frame's document where `frame` is an insert;
/// none for another write's ack. It is what the pieces naming the insert's
/// words are placed at, and what its landed-insert entry keeps (skep #969).
fn minted_by<'a>(frame: &Value, ack: &'a Value) -> Option<&'a str> {
    minted_on(frame["doc"].as_str().filter(|_| frame["op"] == "insert")?, ack)
}

/// Returns the first I-address an insert on `doc` minted, as its ack names
/// it.
///
/// It is the ack's `addr` (A-63) where the address lies in `doc`'s own
/// content I-space (`<doc>.0.1`), which an insert mints into; none for
/// another answer, or for an address of another place (SP-19). It is the one
/// reader of an insert's minted address, the hold's and a follower's alike
/// (`shell/follow.rs`; SP-18).
pub(crate) fn minted_on<'a>(doc: &str, ack: &'a Value) -> Option<&'a str> {
    acked_addr(ack).filter(|addr| i_address(addr).is_some_and(|(prefix, _)| prefix.strip_suffix(".0.1") == Some(doc)))
}

/// Returns the documents an acked write's `/changes` row names.
///
/// As wire.md §The change feed has it — "the target for arrangement writes,
/// the home for link writes, the minted document for mints" — they are read
/// from its frame and its ack.
fn written_docs<'a>(frame: &'a Value, ack: &'a Value) -> Vec<&'a str> {
    let members: &[&str] = match frame["op"].as_str() {
        Some("create_new_document" | "fork" | "version" | "stage" | "publish") => return ack["addr"].as_str().into_iter().collect(),
        Some("make_link" | "emit" | "nullify" | "assert_sup") => &["home"],
        Some("edit_link") => &["d_s", "d_a"],
        _ => &["doc"],
    };
    members.iter().filter_map(|m| frame[*m].as_str()).collect()
}

#[cfg(test)]
mod tests;
