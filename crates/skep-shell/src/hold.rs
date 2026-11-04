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
//! ([`classify`]: §3c.4's hold(cause) / reissue / neither) — an ack carried
//! and its `at` noted for the `base` of the next hold on every document it
//! names (§3c.2), a later position never lowered by an earlier one read
//! after it, and entered in the board's acked positions, which the resend's
//! read never takes for a line's lost landing ([`BoardHold::acked`]); a
//! reissue-class answer reissued within the call, a
//! `write_busy` once after [`WRITE_BUSY_WAIT`], a first and second
//! `durability` as-is, so the page meets the ack or the next refusal
//! (§4b.1's `op` row); and anything else faced at the act, save a burst's
//! hold-class answer or refused run, which is held, and a burst the board
//! refuses as typed against an older state of its document
//! (`arrangement_moved`): shifted through the change by the page's anchors
//! and sent again within the call where the span they bound holds the
//! burst's own units still (`resend`'s shift, skep #442, #751), else held
//! as a moved document, the board's verdict kept on its line. A write the
//! hold never holds is faced where a burst's would be held (§3c.4: "a
//! non-burst write that fails … is faced at its act") — and the eight of
//! them §3c.4 names ([`UNHOLDABLE_WRITES`], `publication.confirm`'s send
//! beside them) meeting a hold that stands at the board before any dial —
//! the own node stopped, the write path poisoned, the writes halted — are
//! REFUSED at once with the hold's cause as the refusal's name
//! ([`Holds::unholdable_refusal`]), never held and never dialed, the page
//! answering before it composes; a board that is unreachable is no such
//! hold, its dial failing as it fails.
//! A write takes that path under a session that may write alone: the `op`
//! row refuses a bare session's before any dial (`SessionEntry::may_write`),
//! and the resend sends under no bare session. A write the session's key
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
//! `behind` it; and it is held without a dial where a hold stands — the own
//! node stopped, the board halted, a line of the principal's already held.
//! The resend sends each held line through the same reader of an answer, a
//! reissue-class answer there reissued at the next probe; a line no landing
//! of which is found [`HAND_OVER_DEADLINE`] after its first failed send,
//! whatever the failure, is handed to the person, a refused run under
//! `answers_lost`, and one the board refuses at a resend under a code the
//! table holds nowhere is handed over at once, a refused run under the
//! board's token (§3c.4).
//! The anchors a burst carries over the bridge (`held::Anchors`) ride with
//! its line and never with its frame: the frame dialed is the wire's frame,
//! as the attest is stripped at the hold and composed at every send.
//!
//! **The queue** is each principal's [`HeldQueue`], in `k` order across the
//! board's documents: copied to `held/<chain>/principal-<n>.held` where this
//! shell holds the board's directory (§3c.1); to the PENDING directory,
//! `held/pending/<hash of the origin dialed>/`, while the board's head record
//! stands and cannot be read or a claimed board serves none (§3c.1; skep
//! #725) — its lines joined into the board's own file, in `k` order, once
//! `H.1` reads ([`Directory::Pending`], `held`'s join); and kept in memory
//! alone where the directory is out of reach — its lock held by another
//! process among the causes: ONE SHELL PER DATA DIRECTORY (§3c.3), a second
//! launch hands its address to the running client and exits, so no second
//! holder keeps a burst in memory as its own, and the lock is tried again at
//! the next session's open and probe; or the board away, or unclaimed, at
//! the first touch — such lines joining the board's file by the same rule
//! the moment the directory is this shell's. The queue is opened only under
//! a session as its principal (P39) — at the session's open, or at the first
//! touch after it — by the principal's door, [`Holds::principal_hold`],
//! which every act on a principal's queue takes, a burst's among them once
//! the burst's door has let it in. The probe ([`Holds::probe`]) and the
//! resend it lets run, which drain the queue once the board returns, are the
//! child module `resend`'s: one read of the board's head per probe decides
//! the directory and which documents are skipped ([`Holds::establish`]).
//!
//! **Each board's hold its own lock**, the boards fixed at the open: a
//! board's appends, each synced to disk, its file's read at a session's open
//! and its resend's bookkeeping hold that board's lock alone, so no board's
//! wait is another's.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_client::board::{acked_at, Answer, Board, ChangesAnswer, ChangesQuery, Health, Rejection};
use skep_client::halt::Halt;
use skep_client::sheet::render_inert;
use skep_client::store::{FileStore, KeyFacts};
use skep_client::{DialError, Origin};
use skep_identity::BoardTerm;
use skep_search::Chain;

use crate::attest::{attest_room, insert_terms, Unattested};
use crate::events::{EventBus, EventName};
use crate::held::{Anchors, Done, HaltWhy, HeldDir, HeldLine, HeldQueue, Opened, Reason, Torn, Unheld, MAX_HELD_FRAME_BYTES, MAX_HELD_LINES};
use crate::refs::BoardEntry;
use crate::refusal::{Name, Refusal};
use crate::sessions::{board_head, SessionEntry, SessionKind, Sessions};
use crate::wire::{document_address, json_len, MAX_FRAME_BYTES};
use crate::Talk;

mod resend;

/// The interim probe cadence (§3c.4): `GET /health` at this interval.
///
/// The probe reads it while a burst is held at a board; the value is open
/// to tuning.
pub const PROBE_CADENCE: Duration = Duration::from_secs(2);

/// A held line's wall-clock deadline: two minutes from its first failed send.
///
/// It is one per line, run from the line's first failed send, whatever the
/// failure (§3c.4; skep #716, #720, #722): a send fails where its dial left,
/// or was answered, and did not land — a lost answer (a timeout, a garbled
/// answer, the board's handler panicking), a `poisoned` answer, a
/// reissue-class answer at its count, a `durability` hold, a refusal the
/// table holds nowhere, the board's refusal of a burst typed against an
/// older state, shifted or not — the person's own first dial among them; a
/// connection never made starts nothing, the board being away, and nor does
/// a request refused before any connection or an attest that could not be
/// composed ([`failed_send`], [`Dialed::failure`]). At the deadline the next
/// read that finds no landing of the line hands it to the person as a
/// refused run, `answers_lost`, naming the last failure and the time
/// elapsed, its `sent` kept and the lines behind it waiting with it
/// (§3c.5); a read that finds its landing keeps it, so the hand-over never
/// sends it twice. A code the table holds nowhere is handed over at once,
/// since it cannot resolve; a shift is refused past the deadline, so a
/// document another writer keeps moving is bounded by the clock alone; and
/// the resend's "sent again" is said once per change of the failure. The
/// clock is in memory, per line, so a relaunch starts it afresh, as the
/// person's `send` does.
pub(crate) const HAND_OVER_DEADLINE: Duration = Duration::from_secs(120);

/// The short wait before a `write_busy` is reissued.
///
/// It is §3c.4's "a silent reissue after a short wait" — interim, open to
/// tuning, as [`PROBE_CADENCE`] is.
const WRITE_BUSY_WAIT: Duration = Duration::from_millis(50);

/// The burst machine's five kinds (§3c.4) — the ops the held store holds.
const BURST_KINDS: [&str; 5] = ["insert", "delete", "copy", "reinstate", "rearrange"];

/// The eight non-burst writes §3c.4 names, which a standing hold refuses.
///
/// Each arriving while the board is stopped, poisoned or its writes halted
/// is refused at once with the hold's cause as its token, never held and
/// never dialed ([`Holds::unholdable_refusal`]); `publication.confirm`'s
/// send, the shot's one carrier, takes the same door with `publish` as its
/// op; `stage`, the staging act's mint (B3-S10), takes it as `fork` does;
/// `set_arrangement`, a draft's whole arrangement set in one write (the
/// landing lane, skep #764), takes it too — no burst, since it is the
/// landing of a merge and no act of the page's hand, and a landing held
/// would land over whatever the hand wrote meanwhile. Every other write
/// outside the five bursts dials as it dials.
pub const UNHOLDABLE_WRITES: [&str; 8] =
    ["fork", "version", "stage", "set_arrangement", "make_link", "nullify", "edit_link", "publish"];

/// Returns whether `frame` is a burst: one of the five kinds.
///
/// §3c.4 says "on a draft under the session" — the kind test is the
/// shell's; a write on a document that is no draft is the board's refusal,
/// permanent, and so a refused run.
fn is_burst(frame: &Value) -> bool {
    frame["op"].as_str().is_some_and(|op| BURST_KINDS.contains(&op))
}

/// §3c.2's causes, as a held line and its answer spell them.
///
/// Beside these, the shell's own `head_unreadable` holds a signed write
/// whose signature could not be made, and a refused run's line carries the
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
}

/// A hand whose row moved a held document (§3c.5; §4b.2's `held` event).
///
/// Each is read off a `/changes` row since the burst's typed state, or since
/// the position the person's last `send` on the document acknowledged the
/// rows through where that is later, where the board refused it as typed
/// against an older state — the one route to a moved document; the resend's
/// read judges no move: this store's own key, another key with the label
/// this shell's key store holds for it, an unsigned hand under local trust,
/// or a row whose testimony the board lost — the data of the three forms the
/// moved face draws, the strings the copy's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hand {
    /// `own`, `other`, `bare` or `lost`.
    pub key: &'static str,
    /// The key's fingerprint, for `own` and `other`.
    pub fingerprint: Option<String>,
    /// The label this shell's key store holds for an `other` key, rendered
    /// inert; absent where the store holds none.
    pub label: Option<String>,
}

impl Hand {
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

/// What a write's dial answered that [`classify`] reads (§3c.4).
///
/// The own node stopped (no dial), an ack and the death signal are not
/// here: a stop holds a burst before any dial, an ack is carried as any
/// `op`'s, and the death signal ends the session. A write the hold never
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
    /// It is reissued once, after [`WRITE_BUSY_WAIT`].
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
/// reissued once, a `durability` twice, its third holding a burst (§3c.4's
/// rider). Counted by the caller as it reissues ([`Reissues::note`]), so
/// every reissue moves the write toward its bound: a write is dialed four
/// times at most within its call. A held line's clock is kept beside them,
/// across its probes ([`Reissues::failed`]): its first failed send, from
/// which [`HAND_OVER_DEADLINE`] runs, and the last failure's token. Not
/// `Copy`, for the token's sake: [`classify`] reads it by reference.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Reissues {
    write_busy: u32,
    durability: u32,
    /// The line's first failed send, from which [`HAND_OVER_DEADLINE`] runs.
    ///
    /// Set at the line's first failed send and never moved later, by the
    /// line's birth where its first dial failed ([`Holds::enter_line`]) and by
    /// each failed send after it; read by no [`classify`]. The person's
    /// `send` clears it, so the clock starts afresh at the line's next failed
    /// send.
    first_failed: Option<Instant>,
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

    /// Notes a failed send of the line at `now`, `token` its failure's.
    ///
    /// The clock starts at the line's first and is never moved later, and
    /// `token` is the last from here. It answers whether `token` differs from
    /// the last failure's token as it stood — a line's first failure among
    /// them — so the resend says "sent again" once per change.
    fn failed(&mut self, token: String, now: Instant) -> bool {
        self.first_failed.get_or_insert(now);
        let changed = self.last.as_deref() != Some(token.as_str());
        self.last = Some(token);
        changed
    }
}

/// Returns the token of the failed send a line's `reason` says, if any.
///
/// A send fails where its dial left, or was answered, and did not land
/// ([`HAND_OVER_DEADLINE`]), so a reason says one unless no dial of the line
/// left: a connection never made (`unreachable`, `sent` false — the same
/// cause with `sent` is an answer lost), a signature not made
/// (`head_unreadable`), or a hold before any dial (`halted`, `stopped`,
/// `behind`). Every other cause is the board's answer: `poisoned`,
/// `durability`, `moved`, a refused run's token. The token is the cause. It
/// reads a dial's own reason, or the reason a line is born with; a held
/// line's reason keeps an earlier dial's `sent` through a resend that never
/// left.
fn failed_send(reason: &Reason) -> Option<&str> {
    let left = match reason.cause.as_str() {
        cause::UNREACHABLE => reason.sent,
        cause::HEAD_UNREADABLE | cause::HALTED | cause::STOPPED | cause::BEHIND => false,
        _ => true,
    };
    left.then_some(reason.cause.as_str())
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
            // No connection was made — the write did not leave.
            DialError::Connect(_) | DialError::Resolve(_) | DialError::Tls(_) => Decision::Hold { cause: cause::UNREACHABLE, sent: false },
            // The request left and its answer was no answer — it may have
            // landed.
            DialError::Timeout(_) | DialError::Io(_) | DialError::Truncated { .. } | DialError::Response(_) | DialError::TooLarge { .. } => {
                Decision::Hold { cause: cause::UNREACHABLE, sent: true }
            }
            // The scheme this build does not hold, or a request refused before
            // any connection opened — faced as built, no probe ends either.
            DialError::NotHeld(_) | DialError::Request(_) => Decision::Neither,
            // A later transport error (the enum is non-exhaustive): the request
            // may have left, so hold `sent: true` — the resend reads first.
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
            // reissue's own `write_busy` is the next refusal, faced.
            "write_busy" => {
                if given.write_busy == 0 {
                    Decision::Reissue(Reissue::WriteBusy)
                } else {
                    Decision::Neither
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
    /// The death signal on the session's token.
    ///
    /// The caller ends the session, and nothing is held (§3c.4: the death
    /// signal is neither).
    Died,
}

/// The person's two acts at a refused run's face or a moved document's.
///
/// They are §4b.1's `resolve` row's, as the row's `act` spells them — read
/// off the call's arguments by [`ResolveAct::named`] alone, so no act
/// reaches the hold that the row does not spell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveAct {
    /// `"drop"`: the line dropped, with the lines after it on its document.
    ///
    /// The lines after it are a refused run's `behind` lines, or a moved
    /// document's later lines.
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
/// The call's answer is `{}` either way.
#[must_use = "a `HandedBack` document's resend waits on the probe its caller hands the board's feed thread"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    /// `"drop"`: the line `done … dropped`, with the lines after it.
    ///
    /// The lines after it on its document — a refused run's `behind` lines,
    /// or a moved document's later lines — are dropped with it.
    Dropped,
    /// `"send"`: the document's waiting lines re-marked `behind`.
    ///
    /// They are handed back to the automatic machine (§3c.4; §4b.1: "handed
    /// to the machine"), each keeping its `sent` and its clock started
    /// afresh — the caller hands the board's feed thread its probe, so the
    /// call answers once the lines are handed back, never after a resend's
    /// ack.
    HandedBack,
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
    /// * its bytes as sent, and as every resend sends them — the attest
    ///   stripped and, under a session whose key attests the kind
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
        let attested = frame["op"].as_str().and_then(|op| session.attesting_key(op)).is_some();
        let sent_bytes = json_len(&frame);
        // The attest a page supplied is never stored, so a resend's frame is
        // the frame without its member — `,"attest":` and the value.
        let stripped_bytes = sent_bytes.saturating_sub(frame.get("attest").map_or(0, |a| r#","attest":"#.len() + json_len(a)));
        let resent_bytes = stripped_bytes + if attested { attest_room() } else { 0 };
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
    /// A reissue-class answer, with its kind.
    ///
    /// It carries the refusal it is, faced where no reissue follows.
    Reissue { kind: Reissue, refusal: Refusal },
    /// An answer faced at the act.
    ///
    /// It is the board's refusal the table holds and reissues nowhere, a
    /// `write_busy` past its one reissue among them, or the shell's own: a
    /// request refused before any connection, or an attest that could not
    /// be composed — the composer's own halt, or a read it made refused.
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

    /// Returns the token of the failed send this dial was, if it was one.
    ///
    /// A send fails where its dial left, or was answered, and did not land
    /// ([`HAND_OVER_DEADLINE`]): every answer but an ack and the death
    /// signal, save a dial that never left — a hold no dial left by
    /// ([`failed_send`]: a connection never made, a signature not made) and
    /// a refusal of the shell's own, a request refused before any connection
    /// or an attest's composer halted.
    /// The token is the held cause, or the board's in the `code:detail`
    /// convention, the token a refused run's line carries.
    ///
    /// **Precondition.** The dial was made, its attest composed: an attest
    /// that could not be composed answers a board's refusal of a read its
    /// composer made as that refusal, which says nothing of the line's send.
    fn failure(&self) -> Option<String> {
        match self {
            Dialed::Held { reason, .. } => failed_send(reason).map(str::to_owned),
            Dialed::Reissue { refusal: Refusal::Board(r), .. } | Dialed::Faced(Refusal::Board(r)) => Some(r.token()),
            Dialed::Acked(_) | Dialed::Reissue { .. } | Dialed::Faced(_) | Dialed::Died => None,
        }
    }
}

/// What a send answers where its attest could not be composed.
///
/// Nothing is dialed ([`Holds::attest_where_owed`]): the death signal met
/// at one of the composer's reads; a read that did not reach the board held
/// like the dial's own failure, `sent: false`, since the write never left; a
/// signature the board's head record could not be read for held
/// `head_unreadable`, `sent: false`, its line carrying the refusal that says
/// why — a burst so held, any other write so refused (SP-14); the
/// composer's own refusal faced.
impl From<Unattested> for Dialed {
    fn from(why: Unattested) -> Dialed {
        match why {
            Unattested::Died => Dialed::Died,
            // The table's transport rows read no reissue count.
            Unattested::Refused(Refusal::Unreachable(e)) => match classify(DialOutcome::Dial(&e), &Reissues::default()) {
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
/// never the frame a held line keeps, which carries no attest (§3c.2).
#[derive(Debug)]
struct AttestedWhereOwed<'f>(Cow<'f, Value>);

/// One line entered in a principal's queue ([`Holds::enter_line`]).
///
/// It is the ordinal the line took, the `held` answer for it, its state and
/// its cause as the `held` event says them.
#[derive(Debug)]
struct LineEntered {
    k: u64,
    answer: Value,
    state: HeldState,
    cause: String,
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
/// `head_unreadable` among them, whose refusal says why it waits and which
/// awaits no act of the person's (P10) save the drop ([`Holds::resolve`];
/// skep #726); `sending` is the resend's, never a line's at rest.
fn line_state(reason: &Reason) -> HeldState {
    if reason.cause == cause::HEAD_UNREADABLE {
        HeldState::Holding
    } else if reason.cause == cause::MOVED {
        HeldState::Moved
    } else if reason.refusal.is_some() {
        HeldState::Refused
    } else {
        HeldState::Holding
    }
}

/// Returns whether a line waits for the person's act.
///
/// It does for a refused run's, or a moved document's (§3c.4, §3c.5): no
/// probe sends it, and `resolve` alone moves it.
fn awaits_act(line: &HeldLine) -> bool {
    matches!(line_state(&line.reason), HeldState::Refused | HeldState::Moved)
}

/// Why a board's directory is not this shell's while another process holds
/// its lock (§3c.3: one shell per data directory).
const ANOTHER_PROCESS: &str = "another process holds this board's held store — one shell per data directory; a second launch hands its address to the running client and exits";

/// The board's held directory (§3c.1) as this shell stands to it.
#[derive(Debug)]
enum Directory {
    /// Not this shell's yet, and why.
    ///
    /// Why: the board unclaimed, serving no `H.1` (§3c.1: no held text), or
    /// away, its head unread; the directory or its lock refused; or the lock
    /// held by another process — which the single-instance rule (§3c.3)
    /// leaves only to the instant a second launch's hand-off has not yet
    /// closed, so nothing is kept here as a second shell's. Tried again at a
    /// session's open and at the probe; the lines held meanwhile are in
    /// memory, and join the board's file the moment the directory is this
    /// shell's ([`Holds::establish`]).
    NotYet(String),
    /// The PENDING directory, `held/pending/<hash of the origin dialed>/`,
    /// this shell's while the board's `H.1` will not read (§3c.1; skep #725).
    ///
    /// The board's head record stands and cannot be read, or a claimed board
    /// serves none — `head_unreadable` (SP-14), `why` its cause — so the
    /// board names no chain yet and its lines go to the pending file, each
    /// synced before its answer as a chain file's is, so a close loses none
    /// and a relaunch dialing the same origin finds them. Made `0700` and
    /// locked as a board's own directory is. Tried again at every probe: a
    /// head read that answers a term makes the directory the board's own
    /// through the join, the pending lines entered into the board's file in
    /// `k` order and the pending file removed; a read that answers anything
    /// else leaves it pending.
    Pending { dir: HeldDir, _lock: File, why: String },
    /// This shell's for its life: the directory, and the `flock` on its lock.
    ThisWindow { dir: HeldDir, _lock: File },
}

impl Directory {
    /// Returns the directory the board's head names (§3c.1).
    ///
    /// `head` is the board's head as `sessions::board_head` classifies it —
    /// the one classifier the attest reads too, so the directory and the
    /// signature agree. A term names the board's own directory, made `0700`
    /// and locked; `head_unreadable` the pending one, named by `origin`,
    /// made and locked the same way; a board unclaimed (no `H.1`, no held
    /// text) or away (`unreachable`) is not yet this shell's, why said, its
    /// lines in memory as before. Either directory is not yet this shell's
    /// where it or its lock is refused, or another process holds the lock
    /// ([`ANOTHER_PROCESS`]).
    fn of(data_dir: &Path, origin: &Origin, head: &Result<Option<BoardTerm>, Refusal>) -> Directory {
        let (dir, why) = match head {
            Ok(Some(board_term)) => (HeldDir::new(data_dir, Chain::from_bytes(board_term.chain)), None),
            Ok(None) => return Directory::NotYet("the board serves no H.1, whose chain names its held store's directory".to_string()),
            Err(Refusal::Halt { name: Name::HEAD_UNREADABLE, face }) => (HeldDir::pending(data_dir, origin), Some(face.cause.clone())),
            Err(Refusal::Unreachable(e)) => return Directory::NotYet(format!("the board could not be reached to read its H.1: {e}")),
            Err(refusal) => return Directory::NotYet(format!("the board's H.1 could not be read: {refusal}")),
        };
        match dir.ensure().and_then(|()| dir.try_lock()) {
            Ok(Some(lock)) => match why {
                None => Directory::ThisWindow { dir, _lock: lock },
                Some(why) => Directory::Pending { dir, _lock: lock, why },
            },
            Ok(None) => Directory::NotYet(ANOTHER_PROCESS.to_string()),
            Err(e) => Directory::NotYet(format!("the held store could not be made or locked: {e}")),
        }
    }
}

/// The key the `held` event's memory keeps a document's last state under:
/// the board's reference, the session's and the document ([`Holds::last_emitted`]).
type HeldKey = (String, String, String);

/// The board's head as the hold last read it, for the one `Talk` line at
/// each change of its state (skep #727; SP-11).
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

/// Where a principal's held lines are kept at a board (§3c.3).
#[derive(Debug)]
enum Custody {
    /// Not yet opened.
    ///
    /// The next touch under a session of the principal opens its file.
    Unopened,
    /// In `principal-<n>.held`, each line synced before its answer.
    File,
    /// In memory alone, the file out of this shell's reach.
    ///
    /// Each answer carries why as `unwritable` — the board's directory not
    /// yet this shell's ([`Directory::NotYet`]'s why: the board unclaimed or
    /// away at the first touch, another process's lock among the causes), or
    /// the file the device refused. The lines join the board's file the
    /// moment its directory is this shell's ([`Holds::establish`]'s join):
    /// each keeps its ordinal where the file's queue holds no line and its
    /// next ordinal is at or below theirs, else they are renumbered from it
    /// and `held` re-said for their documents — so no line waits for an
    /// empty queue to reach disk. Where the join is refused by the device,
    /// or the directory stays out of reach, the file is opened at a later
    /// touch that finds the queue empty, as before.
    Unwritable(String),
    /// Nowhere: P38's halt (§3c.3).
    ///
    /// No burst is sent and no line held for the principal at this board,
    /// each act answered `store_halted` by the principal's door,
    /// [`Holds::principal_hold`], which every act takes.
    Halted { path: PathBuf, why: HaltWhy },
}

impl Custody {
    /// Returns whether the custody stands for the shell's life.
    fn settled(&self) -> bool {
        matches!(self, Custody::File | Custody::Halted { .. })
    }
}

/// One principal's hold at one board.
///
/// It holds where its lines are kept, the queue, the position of its latest
/// write per document whose position the shell knows — the greatest of its
/// acks' and of the landings the resend's read found, each noted by
/// [`PrincipalHold::note_position`]: the `base` a hold on that document
/// takes ([`PrincipalHold::base_of`], §3c.2), the position the resend's
/// read of the line starts from, read before the burst's dial so an ack
/// read during the dial never lifts it past the line's own landing — the
/// reissues each line's resend has been given and its clock, its first
/// failed send and its last failure's token, kept across its probes
/// ([`Reissues`]), and the position each line's moved document was
/// acknowledged through by the person's `send`
/// ([`PrincipalHold::seen_through`]). An ack touches no standing line's
/// base: a line held keeps the base it was held at, raised only behind a
/// line kept on its document (`HeldQueue::done`) and by the person's `send`
/// on a moved document (`HeldQueue::remark_raised`, [`Holds::resolve`]).
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
    last_acked: HashMap<String, u64>,
    reissues: HashMap<u64, Reissues>,
    /// The position the person's `send` acknowledged each line's moved
    /// document through, by the line's ordinal (§3c.4; skep #757).
    ///
    /// It is set at the person's `send` on a moved document for each line
    /// it re-marks, at the position the board's verdict read through — the
    /// one the line's `base` is raised to ([`Holds::resolve`]) — and taken
    /// out where the line leaves the queue, as its reissues are
    /// ([`Holds::done_line`]). The hands a moved face names are read since
    /// it where it stands past the burst's typed state
    /// ([`Holds::hands_since_typed_state`]): the rows the person
    /// acknowledged are named no more. Never the line's `base`, which can
    /// stand past a burst's typed state for reasons of its own — an ack, a
    /// line kept before it — and would drop real hands from a first moved
    /// face. In memory, as the clock is: a relaunch forgets it, and the
    /// first face after one names the acknowledged hands again, while the
    /// raised `base` persists.
    seen_through: HashMap<u64, u64>,
}

impl PrincipalHold {
    /// Returns a hold not yet opened, its file's header to name `account`.
    fn new(account: &str) -> PrincipalHold {
        PrincipalHold { custody: Custody::Unopened, account: account.to_string(), queue: HeldQueue::in_memory(), last_acked: HashMap::new(), reissues: HashMap::new(), seen_through: HashMap::new() }
    }

    /// Returns whether the hold's lines were held before the board's
    /// directory was this shell's, and so join its file at the directory's
    /// establishment ([`Holds::establish`]).
    ///
    /// They were where the queue's file is a pending directory's, or where
    /// the lines are in memory alone and some stand.
    fn joins(&self) -> bool {
        match self.custody {
            Custody::File => self.queue.is_pending(),
            Custody::Unwritable(_) => !self.queue.lines().is_empty(),
            Custody::Unopened | Custody::Halted { .. } => false,
        }
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
    fn count(&self, doc: &str) -> u64 {
        self.queue.lines().iter().filter(|l| l.doc == doc).count() as u64
    }
}

/// One board's hold.
///
/// It holds its directory, the three states that hold every burst before
/// any dial — and refuse the six unholdable writes at once — the positions
/// this shell acked at the board, and each principal's queue.
#[derive(Debug)]
struct BoardHold {
    directory: Directory,
    /// The positions this shell acked at the board (§3c.5).
    ///
    /// Every ack [`Holds::note_ack`] reads enters its `at`, whatever
    /// documents its row names, and every landing the resend's read finds
    /// enters its position; in memory, for the shell's life. The resend's
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
    /// restarts, so the six unholdable writes are refused here without a
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
    principals: HashMap<u64, PrincipalHold>,
}

impl BoardHold {
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
    /// Whether a resend drains this board now.
    ///
    /// One drain per board runs at a time, whatever thread reaches
    /// [`Holds::probe`] — the board's feed thread every `PROBE_CADENCE`, at
    /// its daemon-running tick, and at the hand-overs of `resolve(send)` and
    /// `set_node_state(Running)` — so none double-sends.
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

/// The holds: every board's hold, shared by the shell and the feed threads.
///
/// The shell shares it for the `op` row's one path, `held` and `resolve`, a
/// session's open and `set_node_state`; the boards' feed threads for the
/// probe, the `/health` read and the daemon-running end. The boards are the
/// shell's, fixed at its open, each under its own lock. A method about a
/// session reaches its board through the session — its `board_reference`
/// the hold's key, its `board` the board dialed — and the board-wide ones
/// (`probe`, `set_node_stopped`, `node_stopped`, `note_health`) take the
/// board's reference.
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
    /// The `held` event last emitted per (board, session, document): its
    /// state and count ([`Holds::emit_held`]).
    ///
    /// The event goes out once per change of a document's state (skep #727):
    /// an emit of the pair last emitted for its key is none. A leaf lock,
    /// taken inside `emit_held` alone and never held while another lock is
    /// taken — the emit is made under the board's lock from `resolve` and a
    /// hold among others, so the memory lives beside the boards' locks, not
    /// under one. A document kept with no line left clears its key.
    last_emitted: Mutex<HashMap<HeldKey, (HeldState, u64)>>,
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
    /// until a session opens at one.
    pub fn new(sessions: Arc<Sessions>, bus: Arc<EventBus>, key_store: Arc<FileStore>, data_dir: PathBuf, talk: Talk, boards: impl IntoIterator<Item = Arc<BoardEntry>>) -> Arc<Holds> {
        let boards = boards
            .into_iter()
            .map(|entry| {
                let hold = BoardHold {
                    directory: Directory::NotYet("no session has opened at this board yet".to_string()),
                    acked: HashSet::new(),
                    writes_halted: false,
                    poisoned: false,
                    node_stopped: false,
                    head: HeadState::Unknown,
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
    /// Its clock starts where it stands unstarted, at [`Holds::now`], and
    /// `token` is the last failure's from here. It answers whether `token`
    /// differs from the last failure's as it stood.
    fn note_failure(&self, board_reference: &str, principal: u64, k: u64, token: String) -> bool {
        let now = self.now();
        self.with_principal(board_reference, principal, |ph| ph.reissues.entry(k).or_default().failed(token, now)).unwrap_or(true)
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
        self.with_principal(board_reference, principal, |ph| ph.queue.lines().iter().find(|l| l.k == k).cloned()).flatten()
    }

    /// Returns how many lines stand on `doc` in the principal's queue.
    fn count_of(&self, board_reference: &str, principal: u64, doc: &str) -> u64 {
        self.with_principal(board_reference, principal, |ph| ph.count(doc)).unwrap_or(0)
    }

    /// Sets the own node's stopped state as its owner reports it (§3c.4).
    ///
    /// While it stands, every burst holds `stopped`, and the probe waits for
    /// `Running` to resend.
    pub fn set_node_stopped(&self, board_reference: &str, stopped: bool) {
        self.lock(board_reference).node_stopped = stopped;
    }

    /// Returns whether the board's node stands stopped by its owner's act.
    ///
    /// The act is [`Holds::set_node_stopped`]'s. It is what `probe` answers
    /// for the own node, and what the feed reads when the board's stream
    /// fails, so a deliberate stop is announced `stopped` once and never
    /// `unreachable` beside it. A board that is not the own node answers
    /// false.
    pub fn node_stopped(&self, board_reference: &str) -> bool {
        self.lock(board_reference).node_stopped
    }

    /// Takes a session opened at the board (§3c.7 items 1 and 4).
    ///
    /// The board's directory is established where it is not yet, and the
    /// session's principal's file read whole under its account — P38's faces
    /// kept, a misplaced file set aside and said in the shell's own window —
    /// so `held(session)` lists its lines at once, a bare session's among
    /// them, and the next probe resends them where a session of the
    /// principal's may write. No other principal's file is opened (P39).
    pub fn open_session(&self, session: &SessionEntry) {
        let slot = self.slot(&session.board_reference);
        // The board's head is read outside the lock, once, where the directory
        // is not yet the board's own (the board keeps a term once read).
        if !matches!(slot.lock().directory, Directory::ThisWindow { .. }) {
            let head = board_head(&slot.board);
            self.note_head(&session.board_reference, &head);
            self.establish(&session.board_reference, slot, &head);
        }
        // A halted file is answered at the principal's next act.
        let _ = self.principal_hold(&mut slot.lock(), session);
    }

    /// Establishes the board's directory where it is not yet the board's own,
    /// from one read of the board's head.
    ///
    /// `head` is the board's head as the caller read it (`sessions::board_head`)
    /// — the session's open reads it once where the directory is not yet the
    /// board's own, and the probe once per probe (`resend`'s `drain`), the one
    /// answer deciding the directory here and the documents the resend skips,
    /// so no probe reads the head twice for the hold's sake. A term makes the
    /// directory the board's own ([`Directory::ThisWindow`]) THROUGH THE JOIN
    /// ([`Holds::join`]): every line held before — in the pending file, or in
    /// memory — enters the board's file first, under the board's lock.
    /// `head_unreadable` makes a directory not yet this shell's the pending one
    /// ([`Directory::Pending`]); a pending directory stays so until a term
    /// reads, whatever else the head answers — its lines are on disk, and a
    /// board away or serving a damaged record says nothing that moves them —
    /// and stays so too where the board's own directory cannot be taken yet.
    /// The directory is made and locked under the board's lock, as the files
    /// are read under it. A hold never comes here: it never dials to learn
    /// where to write.
    fn establish(&self, board_reference: &str, slot: &BoardSlot, head: &Result<Option<BoardTerm>, Refusal>) {
        let mut board_hold = slot.lock();
        let next = match &board_hold.directory {
            Directory::ThisWindow { .. } => return,
            Directory::Pending { .. } if !matches!(head, Ok(Some(_))) => return,
            Directory::NotYet(_) | Directory::Pending { .. } => Directory::of(&self.data_dir, slot.board.dialed(), head),
        };
        match &next {
            // The pending directory keeps the lines while the board's own
            // cannot be taken yet; tried again at the next probe.
            Directory::NotYet(_) if matches!(board_hold.directory, Directory::Pending { .. }) => return,
            Directory::ThisWindow { dir, .. } => {
                if let Directory::Pending { why, .. } = &board_hold.directory {
                    self.say(format_args!("the board's head record (`H.1`) reads: the lines held in the pending held store while it could not be read ({why}) join the board's held file"));
                }
                self.join(board_reference, &mut board_hold, dir, slot.board.dialed());
            }
            Directory::NotYet(_) | Directory::Pending { .. } => {}
        }
        board_hold.directory = next;
    }

    /// Joins into the board's file every line held before its directory was
    /// this shell's (`held`'s join; skep #725, the record's F4).
    ///
    /// It runs under the board's lock at the step to [`Directory::ThisWindow`],
    /// `dir` the board's own directory, made and locked. The lines come from
    /// three places: each live principal's queue where it is the pending file's
    /// or in memory alone ([`PrincipalHold::joins`]); and the pending directory
    /// on disk, named by `origin` ([`HeldDir::pending`]) — the one this hold
    /// stands at, its lock held, or the one an earlier run left, locked for the
    /// join where no other process holds it — whose `principal-<n>.held` files
    /// an earlier run left, a principal with no session now among them. Per
    /// principal ([`Holds::join_principal`]): the board's file is opened as the
    /// principal's door opens it; the checks are made — the pending file's
    /// `board` the origin dialed, the board's file's its chain, else the
    /// pending file set aside and said, nothing joined; the standing lines are
    /// entered in `k` order, an earlier run's before this run's, each written
    /// and synced, and only then is the pending file removed; the ordinals are
    /// kept where the board's queue holds no line and its next ordinal is at
    /// or below theirs, else renumbered, and `held` re-said for every document
    /// whose lines were renumbered, under each session of the principal's at
    /// the board and past the once-per-change memory, so a page or an agent
    /// reads the new ordinals before acting on one. One `Talk` line per
    /// principal joined: the count, and whether renumbered. A join the device
    /// refuses is undone by the queue and said, the principal's lines standing
    /// where they were for the next launch's join.
    fn join(&self, board_reference: &str, board_hold: &mut BoardHold, dir: &HeldDir, origin: &Origin) {
        let BoardHold { directory, principals, .. } = board_hold;
        let earlier = HeldDir::pending(&self.data_dir, origin);
        let (pending, _lock) = match directory {
            Directory::Pending { dir: pending, .. } => (Some(&*pending), None),
            _ if earlier.exists() => match earlier.try_lock() {
                Ok(Some(lock)) => (Some(&earlier), Some(lock)),
                Ok(None) => {
                    self.say("another process holds this board's pending held store; the files an earlier run left there join at the next launch");
                    (None, None)
                }
                Err(e) => {
                    self.say(format_args!("the pending held store could not be locked ({e}); the files an earlier run left there join at the next launch"));
                    (None, None)
                }
            },
            _ => (None, None),
        };
        let mut joining: BTreeSet<u64> = principals.iter().filter(|(_, ph)| ph.joins()).map(|(principal, _)| *principal).collect();
        if let Some(pending) = pending {
            match pending.principals() {
                Ok(on_disk) => joining.extend(on_disk),
                Err(e) => self.say(format_args!("the pending held store could not be listed ({e}); the files an earlier run left there join at the next launch")),
            }
        }
        for principal in joining {
            self.join_principal(board_reference, principals, dir, pending, principal);
        }
    }

    /// Joins one principal's lines into the board's file ([`Holds::join`]).
    ///
    /// `pending` is the pending directory where one stands. This run's lines
    /// — the pending file's, or memory's — are taken out of the hold for the
    /// join and put back where it is refused; an earlier run's pending file
    /// is opened where the live queue is not it. The board's file is opened
    /// under the account the hold names, else the one the earlier run's
    /// header does.
    fn join_principal(&self, board_reference: &str, principals: &mut HashMap<u64, PrincipalHold>, dir: &HeldDir, pending: Option<&HeldDir>, principal: u64) {
        let live = principals.get_mut(&principal).filter(|ph| ph.joins()).map(|ph| std::mem::replace(&mut ph.queue, HeldQueue::in_memory()));
        let restore = |principals: &mut HashMap<u64, PrincipalHold>, live: Option<HeldQueue>| {
            if let (Some(ph), Some(queue)) = (principals.get_mut(&principal), live) {
                ph.queue = queue;
            }
        };
        // An earlier run's pending file, where this run's queue is not it.
        let mut earlier = None;
        if let Some(pending) = pending.filter(|_| !live.as_ref().is_some_and(HeldQueue::is_pending)) {
            match pending.open_file(principal, "") {
                Ok(Opened::Live { queue, aside }) => {
                    self.note_opened(principal, &queue, aside.as_deref());
                    earlier = Some(queue);
                }
                Ok(Opened::Halted { path, why }) => {
                    self.say(format_args!("principal {principal}'s pending held file {} is halted ({}) and is not joined; it stands until a person moves it aside", path.display(), why.token()));
                    return restore(principals, live);
                }
                Err(e) => {
                    self.say(format_args!("principal {principal}'s pending held file could not be read ({e}) and is not joined; it is tried again at the next launch"));
                    return restore(principals, live);
                }
            }
        }
        let account = principals.get(&principal).map(|ph| ph.account.clone()).or_else(|| earlier.as_ref().and_then(|q| q.account().map(str::to_string))).unwrap_or_default();
        let mut chain = match dir.open_file(principal, &account) {
            Ok(Opened::Live { queue, aside }) => {
                self.note_opened(principal, &queue, aside.as_deref());
                queue
            }
            Ok(Opened::Halted { path, why }) => {
                self.say(format_args!("principal {principal}'s held file {} is halted ({}); the lines held before it was reached stand where they were", path.display(), why.token()));
                return restore(principals, live);
            }
            Err(e) => {
                self.say(format_args!("principal {principal}'s held file could not be read ({e}); the lines held before it was reached stand where they were"));
                return restore(principals, live);
            }
        };
        // The checks (§3c.1): a pending file names the board dialed, the
        // board's file its chain — else the pending file is set aside, said,
        // and nothing joined.
        let origin = pending.map(HeldDir::board);
        if let Some(named) = earlier.iter().chain(live.iter()).filter(|queue| queue.is_pending()).find(|queue| queue.board() != origin).map(HeldQueue::board) {
            match pending.map(|p| p.set_aside(principal, named.as_deref())) {
                Some(Ok(aside)) => self.say(format_args!("principal {principal}'s pending held file named another board than the one dialed, and is set aside at {}", aside.display())),
                Some(Err(e)) => self.say(format_args!("principal {principal}'s pending held file named another board than the one dialed, and could not be set aside ({e})")),
                None => {}
            }
            return restore(principals, live);
        }
        if chain.board().is_some_and(|board| board != dir.board()) {
            self.say(format_args!("principal {principal}'s held file names another board than its directory; nothing is joined"));
            return restore(principals, live);
        }
        // The join, an earlier run's lines first, each source's in `k`
        // order; a refused copy undoes its source's and leaves the lines
        // where they were.
        let (mut count, mut renumbered) = (0usize, false);
        if let Some(mut earlier) = earlier {
            match chain.join(&earlier) {
                Ok(joined) => {
                    count += joined.entered.len();
                    renumbered |= joined.renumbered;
                    if let Err(e) = earlier.remove_file() {
                        self.say(format_args!("principal {principal}'s pending held file of an earlier run was joined and could not be removed ({e}); its lines are joined no second time"));
                    }
                }
                Err(refused) => {
                    self.say(format_args!("principal {principal}'s pending held file of an earlier run could not join the board's held file (line {}: {}); it stands, and is tried again at the next launch", refused.k, refused.error));
                    return restore(principals, live);
                }
            }
        }
        let mut entered = Vec::new();
        match live.as_ref().map(|queue| chain.join(queue)) {
            None => {}
            Some(Ok(joined)) => {
                count += joined.entered.len();
                renumbered |= joined.renumbered;
                entered = joined.entered;
            }
            Some(Err(refused)) => {
                self.say(format_args!("principal {principal}'s held lines could not join the board's held file (line {}: {}); they stand where they were, and join at the next launch", refused.k, refused.error));
                return restore(principals, live);
            }
        }
        // The commit: the pending file removed, the hold's queue the board's
        // own, its clocks and acknowledgments re-keyed by the ordinals the
        // lines took, and `held` re-said where they changed.
        let mut renumbered_docs: BTreeSet<String> = BTreeSet::new();
        if let Some(ph) = principals.get_mut(&principal) {
            if let Some(mut queue) = live {
                if queue.is_pending() {
                    if let Err(e) = queue.remove_file() {
                        self.say(format_args!("principal {principal}'s pending held file was joined and could not be removed ({e}); its lines are joined no second time"));
                    }
                }
                let new_k = |old: u64| entered.iter().find(|(from, _)| *from == old).map(|(_, to)| *to);
                ph.reissues = std::mem::take(&mut ph.reissues).into_iter().filter_map(|(k, given)| Some((new_k(k)?, given))).collect();
                ph.seen_through = std::mem::take(&mut ph.seen_through).into_iter().filter_map(|(k, at)| Some((new_k(k)?, at))).collect();
                for (from, to) in &entered {
                    if from != to {
                        renumbered_docs.extend(chain.lines().iter().find(|l| l.k == *to).map(|l| l.doc.clone()));
                    }
                }
            }
            ph.queue = chain;
            ph.custody = Custody::File;
        } else {
            // An earlier run's principal, with no session now: its lines stand
            // in the board's file for the session that opens as it.
            principals.insert(principal, PrincipalHold { custody: Custody::File, queue: chain, ..PrincipalHold::new(&account) });
        }
        for doc in &renumbered_docs {
            let (held, state, cause) = self
                .with_hold(principals, principal, doc)
                .unwrap_or((0, HeldState::Kept, None));
            for session in self.sessions.on_board(board_reference).into_iter().filter(|s| s.facts.principal == principal) {
                self.emit_held_again(&session, doc, held, state, cause.as_deref());
            }
        }
        if count > 0 {
            let plural = if count == 1 { "" } else { "s" };
            let ordinals = if renumbered { "renumbered" } else { "their ordinals kept" };
            self.say(format_args!("principal {principal}: {count} held line{plural} joined the board's held file, {ordinals}"));
        }
    }

    /// Returns a document's standing as the `held` event says it, off the
    /// principal's queue: the lines on it, the state of the one that stands
    /// first, and its cause where the state carries one.
    fn with_hold(&self, principals: &HashMap<u64, PrincipalHold>, principal: u64, doc: &str) -> Option<(u64, HeldState, Option<String>)> {
        let ph = principals.get(&principal)?;
        let head = ph.queue.lines().iter().find(|l| l.doc == doc)?;
        let state = line_state(&head.reason);
        let cause = (state != HeldState::Moved).then(|| head.reason.cause.clone());
        Some((ph.count(doc), state, cause))
    }

    /// Says what a principal's file's open found, in the shell's own window
    /// (P39): a misplaced file set aside, and a crash's tail, each once as the
    /// open's own landing — the next line written cuts the tail.
    fn note_opened(&self, principal: u64, queue: &HeldQueue, aside: Option<&Path>) {
        if let Some(aside) = aside {
            self.say(format_args!("principal {principal}'s held file named another board or principal, and is set aside at {}", aside.display()));
        }
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
    /// of its state once (skep #727; SP-11).
    ///
    /// The state is `head_unreadable` — the record standing and not reading,
    /// served garbled, or owed by a claimed board and not served — or the
    /// head reading, an unclaimed board that owes none among them; a board
    /// away says nothing of its head and moves it not. One `Talk` line as
    /// the head becomes unreadable, with its cause, and one as it reads
    /// again; nothing per probe, and nothing on a healthy board.
    fn note_head(&self, board_reference: &str, head: &Result<Option<BoardTerm>, Refusal>) {
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
    /// takes: a session's open, a burst, a hold, `held` and `resolve`. A
    /// principal whose custody is not settled, and whose queue holds no line,
    /// is opened here under `session`'s account: its file where the board's
    /// directory is this shell's, memory alone otherwise. Under the session
    /// that stands, so the restart arm's re-open is covered too.
    ///
    /// # Errors
    ///
    /// Returns `store_halted` where P38 halted the principal's file (§3c.3):
    /// every act's refusal, answered at the principal's door, so no act
    /// reaches a halted principal's queue.
    fn principal_hold<'b>(&self, board_hold: &'b mut BoardHold, session: &SessionEntry) -> Result<&'b mut PrincipalHold, Refusal> {
        let BoardHold { directory, principals, .. } = board_hold;
        let principal = session.facts.principal;
        let account = session.facts.account.as_deref().unwrap_or("");
        let ph = principals.entry(principal).or_insert_with(|| PrincipalHold::new(account));
        if !ph.custody.settled() && ph.queue.lines().is_empty() {
            match directory {
                // The board's own file, or the pending one while its `H.1`
                // will not read (§3c.1): each line synced before its answer
                // either way, and the pending file's lines joined into the
                // board's own once the record reads (`Holds::establish`).
                Directory::ThisWindow { dir, .. } | Directory::Pending { dir, .. } => match dir.open_file(principal, account) {
                    Ok(Opened::Live { queue, aside }) => {
                        self.note_opened(principal, &queue, aside.as_deref());
                        ph.queue = queue;
                        ph.custody = Custody::File;
                    }
                    Ok(Opened::Halted { path, why }) => ph.custody = Custody::Halted { path, why },
                    Err(e) => ph.custody = Custody::Unwritable(format!("the held file could not be read: {e}")),
                },
                Directory::NotYet(why) => ph.custody = Custody::Unwritable(why.clone()),
            }
        }
        if let Custody::Halted { path, why } = &ph.custody {
            return Err(store_halted(path, *why));
        }
        Ok(ph)
    }

    /// Sends one frame under `session`: the `op` row's session form.
    ///
    /// An `/op-at` frame aside, the frame goes to the board the session
    /// stands at. A burst ([`is_burst`]) enters by the burst's door and may be
    /// held (`send_burst`), `anchors` — the page's, read at the row's door —
    /// riding its line for the shift (skep #442) and read by no other frame;
    /// one of the seven unholdable writes
    /// ([`UNHOLDABLE_WRITES`]) meeting a hold that stands at the board is
    /// refused at once with the hold's cause, never dialed
    /// ([`Holds::unholdable_refusal`]); any other frame — a write the hold
    /// never holds, or a read — is attested where an attest is owed, dialed
    /// and reissued within the call, its ack noted for the base, and every
    /// other answer faced as the refusal it is: a refused run, a lost answer
    /// and a third `durability` among them (§3c.4: "a non-burst write that
    /// fails … is faced at its act"). A write comes here under a session
    /// that may write alone (`SessionEntry::may_write`): the `op` row refuses
    /// a bare session's before it.
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
            Dialed::Held { refusal, .. } | Dialed::Reissue { refusal, .. } | Dialed::Faced(refusal) => OpAnswer::Answered(Err(refusal)),
            Dialed::Died => OpAnswer::Died,
        }
    }

    /// Returns the refusal an unholdable write meets at a standing hold (§3c.4).
    ///
    /// `op` is the write's kind. Where it is one of the seven
    /// ([`UNHOLDABLE_WRITES`]) and a hold stands at the board — the own node
    /// stopped, the write path poisoned, the writes halted, in that order —
    /// the write is refused at once under the cause's own name
    /// (`Name::STOPPED`, `Name::POISONED`, `Name::HALTED`), its detail the
    /// `op`, never held and never dialed; `None` where no hold stands or the
    /// kind is not of the seven, the write then dialing as it dials — a board
    /// that is unreachable is no hold of this kind. The `op` row's session
    /// form asks it through [`Holds::send`]; `publication.confirm` asks it
    /// with `publish` before it composes.
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
    /// Its checks run in this order, the first that holds answering:
    /// admitted by the burst's door ([`Burst::admit`]), its refusal faced at
    /// the act; refused `store_halted` where P38 halted the principal's file
    /// (the principal's door, [`Holds::principal_hold`]); held without a dial
    /// where a hold stands at the board — the own node stopped, else the
    /// board halted, else a line of the principal's already held (`behind`);
    /// else dialed within the call ([`Holds::dial_within_call`]): an ack
    /// carried and its `at` noted; a hold-class answer or a refused run held
    /// and answered `held` — a third `durability` among them (§3c.4's rider);
    /// a burst the board refuses as typed against an older state of its
    /// document shifted through the change and sent again within the call
    /// where it carries anchors ([`Holds::shift_at_first_dial`]), so the page
    /// meets the ack or the next refusal — else, or where the shift is not
    /// exact, held as a moved document and answered `held`, its line
    /// carrying the board's verdict and the `held` event naming the hands
    /// whose rows moved the document — one more read the call waits on
    /// ([`Holds::hands_since_typed_state`]); anything else faced at the act.
    ///
    /// The `base` a held line takes — the position the resend's read of it
    /// starts from (§3c.2) — is read under the board's lock BEFORE the dial,
    /// with the standing hold, and handed to the hold either path takes
    /// ([`Holds::hold_line`] at once, [`Holds::hold`] after the dial): an ack
    /// of another write of the principal's read while the dial is out — a
    /// sibling session's, or the person's on another connection — raises the
    /// base of the next hold alone, never this line's, so the read of a line
    /// whose answer was lost starts below its own landing (skep #737).
    fn send_burst(&self, session: &SessionEntry, frame: Value, anchors: Option<Anchors>) -> OpAnswer {
        let burst = match Burst::admit(frame, session) {
            Ok(burst) => burst.with_anchors(anchors),
            Err(refusal) => return OpAnswer::Answered(Err(refusal)),
        };
        let base = {
            let mut board_hold = self.lock(&session.board_reference);
            // A burst's hold before any dial is the own node stopped, else the
            // writes halted (§3c.4's two for a burst; a `poisoned` answer is
            // the dial's own, its line held `sent: true`), else a line of the
            // principal's already held.
            let standing = if board_hold.node_stopped {
                Some(cause::STOPPED)
            } else if board_hold.writes_halted {
                Some(cause::HALTED)
            } else {
                None
            };
            let (line_stands, base) = match self.principal_hold(&mut board_hold, session) {
                Ok(ph) => (!ph.queue.lines().is_empty(), ph.base_of(&burst.doc, session.opened_at)),
                Err(refusal) => return OpAnswer::Answered(Err(refusal)),
            };
            let hold_cause = standing.or(line_stands.then_some(cause::BEHIND));
            if let Some(cause) = hold_cause {
                return OpAnswer::Answered(self.hold_line(&mut board_hold, session, burst, Reason::of(cause, false), base, &[]));
            }
            base
        };
        match self.dial_within_call(session, burst.frame()) {
            Dialed::Acked(ack) => {
                self.note_ack(session, burst.frame(), &ack);
                OpAnswer::Answered(Ok(ack))
            }
            // The board's verdict on the typed state, and the burst carries
            // its anchors: the shift, within the call.
            Dialed::Held { reason, .. } if reason.cause == cause::MOVED && burst.anchors.is_some() => self.shift_at_first_dial(session, burst, reason, base),
            Dialed::Held { reason, .. } => OpAnswer::Answered(self.hold(session, burst, reason, base)),
            Dialed::Reissue { refusal, .. } | Dialed::Faced(refusal) => OpAnswer::Answered(Err(refusal)),
            Dialed::Died => OpAnswer::Died,
        }
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
    /// this call settles. Then the shift and the shifted dial, the step the
    /// resend takes too ([`Holds::shift_and_send`], the one function):
    /// the shifted frame written to the line before it is dialed, the dial
    /// reissued within the call as a first dial's is. Its answer settles the
    /// line as the resend's answers settle one: an ack keeps it, its `at`
    /// noted, and is the call's answer — no `held` event, the line entered
    /// and settled within one call; the verdict again shifts it again, as
    /// far as the line's deadline lets it — the line born here with its
    /// clock started, the board's first refusal its first failed send, and
    /// every failed send of a shifted dial noted on it
    /// ([`HAND_OVER_DEADLINE`]); a hold-class answer or a refused run
    /// re-marks it, `sent` kept, and answers `held` under that cause; an
    /// answer a first dial faces drops the line, entered for the shift
    /// alone, and faces it; the death signal leaves the line standing for
    /// the session that stands next, the caller ending this one. Where the
    /// shift is not exact — a delete or a rearrange without its span, an
    /// anchor lost or at two places, the span between them cut or refilled,
    /// the read refused, the deadline passed — the line is the moved hold as a
    /// burst without anchors meets it: the newest verdict on the line, the
    /// hands read once ([`Holds::hands_since_typed_state`]), the `held`
    /// event `moved`, the call answered `held`.
    fn shift_at_first_dial(&self, session: &SessionEntry, burst: Burst, reason: Reason, base: u64) -> OpAnswer {
        let (board_reference, principal) = (session.board_reference.as_str(), session.facts.principal);
        let doc = burst.doc.clone();
        let mut verdict = reason.refusal.clone().unwrap_or(Value::Null);
        let entered = {
            let mut board_hold = self.lock(board_reference);
            match self.enter_line(&mut board_hold, session, burst, reason, base) {
                Ok(entered) => entered,
                Err(refusal) => return OpAnswer::Answered(Err(refusal)),
            }
        };
        let (k, mut answer) = (entered.k, entered.answer);
        // Whether a shifted dial left, the mark made before it: the line
        // keeps it through every later answer, as a resend's line does.
        let mut sent = false;
        loop {
            let shifted = match self.shift_and_send(session, k, &verdict, |frame| self.dial_reissuing(session, frame)) {
                Ok(shifted) => shifted,
                Err(why) => {
                    self.say(format_args!("line {k} on {doc} was not shifted ({why}); the document is held as moved"));
                    self.mark_moved(board_reference, principal, &doc, Some((k, verdict.clone())));
                    let moved = Reason { cause: cause::MOVED.to_string(), refusal: Some(verdict), sent };
                    let hands = self.hands_since_typed_state(session, &doc, Some(k), &moved);
                    self.emit_held(session, &doc, self.count_of(board_reference, principal, &doc), HeldState::Moved, None, &hands);
                    return OpAnswer::Answered(Ok(answer));
                }
            };
            sent |= shifted.left;
            // A shifted dial that failed is a failed send of the line, as at
            // a resend; one whose attest could not be composed left nothing.
            if let Some(token) = shifted.left.then(|| shifted.dialed.failure()).flatten() {
                self.note_failure(board_reference, principal, k, token);
            }
            match shifted.dialed {
                Dialed::Acked(ack) => {
                    self.note_ack(session, &shifted.frame, &ack);
                    self.with_principal(board_reference, principal, |ph| self.done_line(ph, k, Done::Kept { at: acked_at(&ack) }));
                    return OpAnswer::Answered(Ok(ack));
                }
                Dialed::Held { reason, .. } if reason.cause == cause::MOVED => {
                    verdict = reason.refusal.unwrap_or(Value::Null);
                }
                Dialed::Held { reason, .. } => {
                    let state = line_state(&reason);
                    let said = reason.cause.clone();
                    self.with_principal(board_reference, principal, |ph| self.remark_line(ph, k, Reason { sent: reason.sent || sent, ..reason }));
                    answer["cause"] = Value::from(said.as_str());
                    self.emit_held(session, &doc, self.count_of(board_reference, principal, &doc), state, Some(&said), &[]);
                    return OpAnswer::Answered(Ok(answer));
                }
                Dialed::Reissue { refusal, .. } | Dialed::Faced(refusal) => {
                    self.with_principal(board_reference, principal, |ph| self.done_line(ph, k, Done::Dropped));
                    return OpAnswer::Answered(Err(refusal));
                }
                Dialed::Died => return OpAnswer::Died,
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
    /// `held` answer ([`Holds::hold_line`]). `base` is the position the
    /// line's resend read starts from (§3c.2), the caller's to have read
    /// before its dial ([`Holds::send_burst`]; [`PrincipalHold::base_of`]) —
    /// a hold made with no dial between reads it the same way, now. A burst
    /// the board refused as typed against an older state is held `moved`,
    /// its event naming the hands whose rows moved the document
    /// ([`Holds::hands_since_typed_state`]), read before the board's lock is
    /// taken, as every dial is made outside it.
    ///
    /// # Errors
    ///
    /// Returns `store_halted` where P38 halted the file, and `held_full`
    /// where the principal's queue is full ([`Holds::hold_line`]).
    pub fn hold(&self, session: &SessionEntry, burst: Burst, reason: Reason, base: u64) -> Result<Value, Refusal> {
        let hands = self.hands_since_typed_state(session, &burst.doc, None, &reason);
        self.hold_line(&mut self.lock(&session.board_reference), session, burst, reason, base, &hands)
    }

    /// Holds one line in the principal's queue at the session's board, and
    /// says so.
    ///
    /// `board_hold` is that board's hold. The line is entered
    /// ([`Holds::enter_line`]) and the `held` event is emitted — a moved
    /// line's naming `hands`, the hands whose rows moved its document, and no
    /// cause, as every moved document's face does — and the answer is the
    /// line's.
    ///
    /// # Errors
    ///
    /// Returns what [`Holds::enter_line`] returns, nothing held.
    fn hold_line(&self, board_hold: &mut BoardHold, session: &SessionEntry, burst: Burst, reason: Reason, base: u64, hands: &[Hand]) -> Result<Value, Refusal> {
        let doc = burst.doc.clone();
        let entered = self.enter_line(board_hold, session, burst, reason, base)?;
        let count = self.principal_hold(board_hold, session)?.count(&doc);
        // `emit_held` touches the bus alone, so it is safe under the board's
        // lock.
        let cause = (entered.state != HeldState::Moved).then_some(entered.cause.as_str());
        self.emit_held(session, &doc, count, entered.state, cause, hands);
        Ok(entered.answer)
    }

    /// Enters one line in the principal's queue at the session's board.
    ///
    /// `board_hold` is that board's hold. The line is the burst as stored,
    /// its frame carrying no attest and its anchors beside it, copied to its
    /// file where it has one, its `base` the caller's — the position of the
    /// principal's latest write on the document that the shell knew when the
    /// burst was sent, its ack's or the landing the resend's read found, or
    /// else the session's open position (§3c.2; [`PrincipalHold::base_of`]).
    /// The line is born here, by every path: where `reason` is a failed send
    /// ([`failed_send`]) — the person's own first dial's, a lost answer, a
    /// `poisoned` or `durability` hold, a refused run or a move, shifted or
    /// not — its clock starts now ([`HAND_OVER_DEADLINE`]), and a hold before
    /// any dial, or one no dial left by, starts none.
    /// Nothing is said: the caller emits the `held` event, or none for a
    /// line it settles within its call ([`Holds::shift_at_first_dial`]). The
    /// answer is `{resp: held, held: <k>, cause}`, and `unwritable` beside
    /// it — why — where the device refused its copy or the file is out of
    /// reach, another process's lock on the board's directory among the
    /// causes (§3c.3).
    ///
    /// # Errors
    ///
    /// Returns `store_halted` where the principal's file is halted
    /// ([`Holds::principal_hold`]), and `held_full` where the principal's
    /// queue holds its budget already (`held::MAX_HELD_FRAME_BYTES`'s bytes,
    /// or `held::MAX_HELD_LINES`'s lines) or its ordinals are spent, and
    /// nothing held.
    fn enter_line(&self, board_hold: &mut BoardHold, session: &SessionEntry, burst: Burst, reason: Reason, base: u64) -> Result<LineEntered, Refusal> {
        let ph = self.principal_hold(board_hold, session)?;
        let (doc, frame, anchors) = burst.into_stored();
        let id = frame["id"].as_str().map(str::to_owned);
        let state = line_state(&reason);
        let cause = reason.cause.clone();
        let failed = failed_send(&reason).map(str::to_owned);
        let entered = ph.queue.hold(&doc, id.as_deref(), base, frame, anchors, reason).map_err(queue_refused)?;
        if let Some(token) = failed {
            ph.reissues.entry(entered.k).or_default().failed(token, self.now());
        }
        let unwritable = match &ph.custody {
            Custody::Unwritable(why) => Some(why.clone()),
            _ => entered.unwritten.map(|e| e.to_string()),
        };
        let mut answer = json!({"resp": "held", "held": entered.k, "cause": cause});
        if let Some(why) = unwritable {
            answer["unwritable"] = Value::from(why);
        }
        Ok(LineEntered { k: entered.k, answer, state, cause })
    }

    /// Notes an acked session write (§3c.2, §3c.5).
    ///
    /// Its `at` enters the board's acked positions ([`BoardHold::acked`]),
    /// whatever documents its row names, and becomes the `base` of the next
    /// hold on every document its row names where it is past the position
    /// noted there, which stands otherwise ([`PrincipalHold::note_position`])
    /// — whatever its kind, a burst's, a mint's or a link's, the first dial's
    /// and the resend's alike, each noted where its answer is read. No
    /// standing line is touched: a line held keeps the base it was held at.
    /// A read, or a refusal, notes nothing.
    fn note_ack(&self, session: &SessionEntry, frame: &Value, ack: &Value) {
        let Some(at) = acked_at(ack) else { return };
        let mut board_hold = self.lock(&session.board_reference);
        board_hold.acked.insert(at);
        let docs = written_docs(frame, ack);
        if docs.is_empty() {
            return;
        }
        let ph = board_hold.principals.entry(session.facts.principal).or_insert_with(|| PrincipalHold::new(session.facts.account.as_deref().unwrap_or("")));
        for doc in docs {
            ph.note_position(doc, at);
        }
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
    /// other (P39).
    ///
    /// # Errors
    ///
    /// Returns `store_halted` where P38 halted the file.
    pub fn lines(&self, session: &SessionEntry) -> Result<Value, Refusal> {
        let mut board_hold = self.lock(&session.board_reference);
        let ph = self.principal_hold(&mut board_hold, session)?;
        Ok(Value::Array(ph.queue.lines().iter().map(line_json).collect()))
    }

    /// Answers `resolve(session, {held, act})` (§3c.4, §4b.1).
    ///
    /// It is checked and acted on under the board's one lock.
    /// [`ResolveAct::Drop`] marks the line and every line held after it on
    /// that document — a refused run's `behind` lines, a moved document's
    /// later lines — `done … dropped`; [`ResolveAct::Send`] re-marks the
    /// document's waiting lines `behind`, each keeping its `sent`, its clock
    /// started afresh at its next failed send ([`HAND_OVER_DEADLINE`]),
    /// handing them back to the automatic machine, and answers at once
    /// ([`Resolved::HandedBack`]): the probe that resends them is the
    /// caller's to hand the board's feed thread.
    ///
    /// **The raise** (§3c.4; skep #757). On a moved document the send first
    /// raises each waiting line's `base` to the position the board's verdict
    /// read through — the `site.current` of its `arrangement_moved`, kept on
    /// the line it refused — a base already past it standing, the raise
    /// written to the held file with the line's re-mark
    /// (`HeldQueue::remark_raised`), a copy the device refuses said as every
    /// re-mark's is. The act is the person's acknowledgment of the rows that
    /// moved the document: each line's read for its own landing starts past
    /// them, and a document held moved again names only the hands since
    /// ([`PrincipalHold::seen_through`]). A document no line of which carries
    /// such a verdict is raised nothing. The lines then re-enter as every
    /// line does: the read, then the send — a stale send shifted where its
    /// span is whole, else held moved again.
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
    /// **The drop on `head_unreadable`** (skep #726). A line held for want
    /// of its signature — the board's head record standing and not reading,
    /// or a claimed board serving none — awaits no act of the person's: no
    /// act of theirs makes the head read, so `send` on it stays
    /// `not_resolvable` and the probe keeps trying it. The DROP alone is
    /// admitted, since the board may never be repaired and the line would
    /// otherwise stand, and fill the queue, for good: the page's statement
    /// says before the act that the write is given up for good. It drops the
    /// line AND every later line of its document, as a refused run's drop
    /// does, though `client.md`'s `resolve` row names that reach for a
    /// refused run and a moved document alone (a word owed to it): a later
    /// burst on the document was composed against the page's text WITH the
    /// dropped burst in it, and the board cannot see that — its typed state
    /// never moved for a burst that never landed — so sent alone it would
    /// land off; the page re-composes them from its editor's text, as at
    /// any drop. In `resolve` alone: [`awaits_act`] and [`line_state`] are
    /// unchanged, so the probe keeps trying such a line until the head reads.
    ///
    /// # Errors
    ///
    /// Its refusals come in this order, the first that holds answering:
    /// `store_halted` where P38 halted the principal's file; `no_such_held`
    /// where no line of ordinal `k` stands; `not_resolvable` where the line
    /// awaits no act of the person's (P10) — save the drop of a line held
    /// `head_unreadable`.
    pub fn resolve(&self, session: &SessionEntry, k: u64, act: ResolveAct) -> Result<Resolved, Refusal> {
        let mut board_hold = self.lock(&session.board_reference);
        let ph = self.principal_hold(&mut board_hold, session)?;
        let Some(line) = ph.queue.lines().iter().find(|l| l.k == k) else { return Err(Refusal::shell(Name::NO_SUCH_HELD, json!({"held": k}))) };
        // A line awaiting the person's act alone takes one (P10), save the
        // drop of a line held for want of its signature (skep #726).
        let droppable = act == ResolveAct::Drop && line.reason.cause == cause::HEAD_UNREADABLE;
        if !awaits_act(line) && !droppable {
            return Err(Refusal::shell(Name::NOT_RESOLVABLE, json!({"held": k})));
        }
        let doc = line.doc.clone();
        match act {
            ResolveAct::Drop => {
                let (count, state) = self.drop_run(ph, k, &doc);
                // `emit_held` touches the bus alone, so it is safe under the
                // board's lock.
                self.emit_held(session, &doc, count, state, None, &[]);
                Ok(Resolved::Dropped)
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
                // named no more. A document whose lines carry no such verdict
                // is re-marked as it stands.
                let waiting: Vec<(u64, bool)> = ph.queue.lines().iter().filter(|l| l.doc == doc && awaits_act(l)).map(|l| (l.k, l.reason.sent)).collect();
                let through = ph.queue.lines().iter().filter(|l| l.doc == doc && l.reason.cause == cause::MOVED).find_map(|l| l.reason.refusal.as_ref()?["site"]["current"].as_u64());
                for (k, sent) in waiting {
                    let behind = Reason::of(cause::BEHIND, sent);
                    match through {
                        Some(at) => {
                            self.remark_raised_line(ph, k, behind, at);
                            let seen = ph.seen_through.entry(k).or_insert(at);
                            *seen = (*seen).max(at);
                        }
                        None => self.remark_line(ph, k, behind),
                    }
                    if let Some(given) = ph.reissues.get_mut(&k) {
                        given.first_failed = None;
                        given.last = None;
                    }
                }
                Ok(Resolved::HandedBack)
            }
        }
    }

    /// Drops the line `from` and every line after it on that document.
    ///
    /// The `"drop"` marks them — a refused run's `behind` lines, a moved
    /// document's later lines — `done … dropped`, the file compacting where
    /// the queue empties, and answers for the `held` event its caller emits
    /// under the session that acted: the lines that stand on the document,
    /// and the state of the one that stands first now — a moved line held
    /// before the dropped one keeps the document `moved` — `kept` only where
    /// no line stands.
    fn drop_run(&self, ph: &mut PrincipalHold, from: u64, doc: &str) -> (u64, HeldState) {
        let ks: Vec<u64> = ph.queue.lines().iter().filter(|l| l.doc == doc && l.k >= from).map(|l| l.k).collect();
        for k in ks {
            self.done_line(ph, k, Done::Dropped);
        }
        let head = ph.queue.lines().iter().find(|l| l.doc == doc);
        (ph.count(doc), head.map_or(HeldState::Kept, |l| line_state(&l.reason)))
    }

    /// Notes and answers the `writes.halted` of the board's `/health`.
    ///
    /// The `/health` is as the feed's tick or the probe read it; its
    /// `writes.halted` (wire.md §The other endpoints) is noted — every burst
    /// holds `halted` from the first `true` to the next `false` (§3c.4) —
    /// and answered. A read that says writes go ends a `poisoned` state too:
    /// a poisoned board answers `writes.halted` true until its restart, so
    /// the first `false` after a `poisoned` answer is the restart's.
    pub fn note_health(&self, board_reference: &str, health: &Health) -> bool {
        let writes_halted = health.body["writes"]["halted"].as_bool().unwrap_or(false);
        let mut board_hold = self.lock(board_reference);
        board_hold.writes_halted = writes_halted;
        if !writes_halted {
            board_hold.poisoned = false;
        }
        writes_halted
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
        Ok(AttestedWhereOwed(session.attest(&self.key_store, frame)?))
    }

    /// Dials an [`AttestedWhereOwed`] frame once under `session`.
    ///
    /// The dial goes to the board the session stands at, its answer read
    /// once through [`classify`], `given` the reissues this write has been
    /// given. A non-200 is read by its code, so `write_busy`'s 503 meets its
    /// row. A `poisoned` answer is noted at the board's hold: the six
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

    /// Re-marks one line in place, its ordinal kept.
    ///
    /// It serves a hold that recurs, a refused run, a moved re-facing and the
    /// mark a resend writes before its dial; a copy refused, by the device or
    /// past the file's re-mark budget, is said on `Talk`, the queue taking the
    /// reason all the same.
    fn remark_line(&self, ph: &mut PrincipalHold, k: u64, reason: Reason) {
        if let Err(e) = ph.queue.remark(k, reason) {
            self.say(format_args!("line {k}'s re-mark could not be written ({e}); a reopen reads its earlier one"));
        }
    }

    /// Re-marks one line in place and raises its `base` to `at`, its
    /// ordinal kept.
    ///
    /// It serves the person's `send` on a moved document
    /// ([`Holds::resolve`]); a copy refused, by the device or past the file's
    /// re-mark budget, is said on `Talk` as [`Holds::remark_line`] says one,
    /// the queue taking the reason and the raised base all the same.
    fn remark_raised_line(&self, ph: &mut PrincipalHold, k: u64, reason: Reason, at: u64) {
        if let Err(e) = ph.queue.remark_raised(k, reason, at) {
            self.say(format_args!("line {k}'s re-mark could not be written ({e}); a reopen reads its earlier one"));
        }
    }

    /// Takes one line out of the queue, whatever the disk did.
    ///
    /// A `done` the device refused is said on `Talk`, and so is a held
    /// file the volume would not remove once every line in it was done —
    /// the store appends on to it. The line's reissues and the position
    /// its moved document was acknowledged through go with it.
    fn done_line(&self, ph: &mut PrincipalHold, k: u64, done: Done) {
        if let Ok(settled) = ph.queue.done(k, done) {
            if let Some(e) = settled.unwritten {
                self.say(format_args!("line {k} is settled, and its `done` could not be written ({e}); a reopen reads it as held, and its read decides it"));
            }
            if let Some((path, e)) = settled.unremoved {
                self.say(format_args!("every held line is done, and the held file {} could not be removed ({e}); it stands, and the next line is appended to it", path.display()));
            }
        }
        ph.reissues.remove(&k);
        ph.seen_through.remove(&k);
    }

    /// Emits the `held` event (§4b.2) at the session's board, once per change
    /// of the document's state.
    ///
    /// It is `{board, session, doc, held, state, cause?, hands?}`, under the
    /// session the change was made for — `hands` with the `moved` state
    /// alone, the hands whose rows moved the document (§3c.5), each once. An
    /// emit of the state and count last emitted for the same board, session
    /// and document is none (skep #727): a document's state is said as it
    /// changes, never again per probe; the first emit for a key is always
    /// made, and a document kept with no line left clears its key
    /// ([`Holds::last_emitted`]). The memory's lock is a leaf, taken here
    /// alone and released before the bus is reached, so the emit is safe
    /// under the board's lock as it is without one.
    fn emit_held(&self, session: &SessionEntry, doc: &str, held: u64, state: HeldState, cause: Option<&str>, hands: &[Hand]) {
        let key = (session.board_reference.clone(), session.reference.clone(), doc.to_string());
        {
            let mut last = self.last_emitted.lock().expect("the held events' memory");
            if last.get(&key) == Some(&(state, held)) {
                return;
            }
            if state == HeldState::Kept && held == 0 {
                last.remove(&key);
            } else {
                last.insert(key, (state, held));
            }
        }
        let mut data = json!({"board": session.board_reference, "session": session.reference, "doc": doc, "held": held, "state": state.as_str()});
        if let Some(c) = cause {
            data["cause"] = Value::from(c);
        }
        if !hands.is_empty() {
            data["hands"] = Value::Array(hands.iter().map(Hand::json).collect());
        }
        self.bus.emit(EventName::Held, data);
    }

    /// Emits the `held` event whatever was last emitted for its key.
    ///
    /// It is the join's re-emit for a document whose lines were renumbered
    /// ([`Holds::join`]): the state and the count may stand as they were
    /// while the ordinals moved, so the memory's key is cleared first and
    /// the page reads the lines again by `held(session)`.
    fn emit_held_again(&self, session: &SessionEntry, doc: &str, held: u64, state: HeldState, cause: Option<&str>) {
        self.last_emitted.lock().expect("the held events' memory").remove(&(session.board_reference.clone(), session.reference.clone(), doc.to_string()));
        self.emit_held(session, doc, held, state, cause, &[]);
    }

    /// Returns the hands whose rows moved a document past a burst's typed
    /// state (§3c.5; §4b.2's `held` event).
    ///
    /// `reason` is the line's as a dial held it, and `k` the line's ordinal
    /// where it has one — none for a first dial's hold, whose line is
    /// entered after the read. Where `reason` is `moved` with the board's
    /// verdict — the burst refused `arrangement_moved` — the rows are read
    /// once since the later of the typed state the verdict echoes
    /// (`site.as_of`) and the position the person's last `send` on the
    /// document acknowledged the rows through, where one stands for line `k`
    /// ([`PrincipalHold::seen_through`], §3c.4):
    /// `GET /changes?since=<since>&under=<doc>&drafts=true` under the
    /// session, the rows that moved the document past the burst and that the
    /// person has not acknowledged, their hands named each once
    /// ([`Holds::hands_of`]). So a document moved again after the person's
    /// `send` names the hands since it alone, and a first moved face names
    /// every hand since the typed state, whatever the line's `base`, which
    /// can stand past the typed state for reasons of its own. The
    /// acknowledgment is the shell's memory, as a line's clock is: a relaunch
    /// forgets it, and the first face after one names the acknowledged hands
    /// again, the line's raised `base` persisting. A page whose `more` stands
    /// names the hands of the page it holds, the rows past it unread; a read
    /// the board answers with no page — a refusal, the death signal, no
    /// answer — names none, the document faced moved all the same. Any other
    /// reason reads nothing and names none.
    fn hands_since_typed_state(&self, session: &SessionEntry, doc: &str, k: Option<u64>, reason: &Reason) -> Vec<Hand> {
        let typed = match &reason.refusal {
            Some(verdict) if reason.cause == cause::MOVED => verdict["site"]["as_of"].as_u64(),
            _ => None,
        };
        let Some(typed) = typed else { return Vec::new() };
        // The rows the person's `send` acknowledged are named no more.
        let seen = k.and_then(|k| self.with_principal(&session.board_reference, session.facts.principal, |ph| ph.seen_through.get(&k).copied()).flatten());
        let since = seen.map_or(typed, |seen| seen.max(typed));
        match session.board.changes(Some(&session.token), &ChangesQuery { since, under: Some(doc), drafts: true, limit: None }) {
            Ok(ChangesAnswer::Page(page)) => self.hands_of(session, &page.changes),
            _ => Vec::new(),
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
    /// other key, its fingerprint carried and the label this shell's key
    /// store holds for it rendered inert where the store holds that key — a
    /// store that cannot be listed gives no label, said on `Talk` once per
    /// read (SP-12, SP-14) and never read as a store holding no keys.
    fn hands_of(&self, session: &SessionEntry, rows: &[Value]) -> Vec<Hand> {
        let own_fingerprint = match &session.facts.kind {
            SessionKind::Signed { fingerprint, .. } => Some(fingerprint.to_hex()),
            SessionKind::Bare => None,
        };
        let mut labels: Option<Vec<KeyFacts>> = None;
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
                                self.say(format_args!("the key store could not be listed to label another hand's key ({e}); the hand is named by its fingerprint alone"));
                                Vec::new()
                            }
                        });
                        let label = keys.iter().find(|k| k.fingerprint.to_hex() == key).and_then(|k| k.label.as_deref()).map(render_inert);
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
/// It is the principal's queue full — its frames' bytes, its lines or its
/// ordinals — or — never for a burst [`Burst::admit`] let in — a line no
/// reader of the file reads.
fn queue_refused(why: Unheld) -> Refusal {
    match why {
        Unheld::Full { held_bytes, frame_bytes, held_lines } => Refusal::shell(
            Name::HELD_FULL,
            json!({"held_bytes": held_bytes, "frame_bytes": frame_bytes, "cap": MAX_HELD_FRAME_BYTES, "held_lines": held_lines, "line_cap": MAX_HELD_LINES}),
        ),
        Unheld::Unreadable => Refusal::malformed("frame.doc"),
    }
}

/// Returns P38's halt face for `held(session)` and every act (§3c.3).
fn store_halted(path: &Path, why: HaltWhy) -> Refusal {
    Refusal::shell(Name::STORE_HALTED, json!({"path": path.display().to_string(), "why": why.token()}))
}

/// Returns one held line as `held(session)` lists it (§4b.1).
///
/// It holds the line's members save `id`, `anchors` beside a line whose
/// burst carried them, `refusal` beside a refused run's or a moved line's.
fn line_json(l: &HeldLine) -> Value {
    let mut line = json!({"held": l.k, "doc": l.doc, "base": l.base, "frame": l.frame, "cause": l.reason.cause, "sent": l.reason.sent, "time": l.time});
    if let Some(anchors) = &l.anchors {
        line["anchors"] = anchors.json();
    }
    if let Some(r) = &l.reason.refusal {
        line["refusal"] = r.clone();
    }
    line
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
