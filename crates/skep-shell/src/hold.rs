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
//! after it; a reissue-class answer reissued within the call, a
//! `write_busy` once after [`WRITE_BUSY_WAIT`], a first and second
//! `durability` as-is, so the page meets the ack or the next refusal
//! (§4b.1's `op` row); and anything else faced at the act, save a burst's
//! hold-class answer or refused run, which is held. A write the hold never
//! holds is faced where a burst's would be held (§3c.4: "a non-burst write
//! that fails … is faced at its act") — and the six of them §3c.4 names
//! ([`UNHOLDABLE_WRITES`], `publication.confirm`'s send beside them) meeting
//! a hold that stands at the board before any dial — the own node stopped,
//! the write path poisoned, the writes halted — are REFUSED at once with
//! the hold's cause as the refusal's name ([`Holds::unholdable_refusal`]),
//! never held and never dialed, the page answering before it composes; a
//! board that is unreachable is no such hold, its dial failing as it fails.
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
//! reissue-class answer there reissued at the next probe, and a line whose
//! resends keep losing their answer handed to the person after
//! [`MAX_LOST_ANSWERS`] of them, a refused run under `answers_lost` (§3c.4).
//!
//! **The queue** is each principal's [`HeldQueue`], in `k` order across the
//! board's documents: copied to `held/<chain>/principal-<n>.held` where this
//! shell holds the board's directory (§3c.1), kept in memory alone where
//! the directory is out of reach — its lock held by another process among
//! the causes: ONE SHELL PER DATA DIRECTORY (§3c.3), a second launch hands
//! its address to the running client and exits, so no second holder keeps a
//! burst in memory as its own, and the lock is tried again at the next
//! session's open and probe — and opened only under a session as its
//! principal (P39) — at the session's
//! open, or at the first touch after it — by the principal's door,
//! [`Holds::principal_hold`], which every act on a principal's queue takes,
//! a burst's among them once the burst's door has let it in. The probe
//! ([`Holds::probe`]) and the resend it lets run, which drain the queue once
//! the board returns, are the child module `resend`'s.
//!
//! **Each board's hold its own lock**, the boards fixed at the open: a
//! board's appends, each synced to disk, its file's read at a session's open
//! and its resend's bookkeeping hold that board's lock alone, so no board's
//! wait is another's.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};
use skep_client::board::{acked_at, Answer, Board, Health, Rejection};
use skep_client::halt::Halt;
use skep_client::sheet::render_inert;
use skep_client::store::{FileStore, KeyFacts};
use skep_client::DialError;
use skep_identity::BoardTerm;
use skep_search::Chain;

use crate::attest::{attest_room, insert_terms, Unattested};
use crate::events::{EventBus, EventName};
use crate::held::{Done, HaltWhy, HeldDir, HeldLine, HeldQueue, Opened, Reason, Torn, Unheld, MAX_HELD_FRAME_BYTES, MAX_HELD_LINES};
use crate::refs::BoardEntry;
use crate::refusal::{Name, Refusal};
use crate::sessions::{SessionEntry, SessionKind, Sessions};
use crate::wire::{document_address, json_len, MAX_FRAME_BYTES};
use crate::Talk;

mod resend;

/// The interim probe cadence (§3c.4): `GET /health` at this interval.
///
/// The probe reads it while a burst is held at a board; the value is open
/// to tuning.
pub const PROBE_CADENCE: Duration = Duration::from_secs(2);

/// The lost answers a held line's resends take before it is the person's.
///
/// A resend whose answer is lost — a timeout, a garbled answer, the board's
/// handler panicking (`internal_panic`): the table's `unreachable` rows with
/// `sent` — counts one try; a connection never made counts none, nothing
/// having left. At the bound the next read that finds no landing of the
/// line hands it to the person as a refused run, `answers_lost`, its `sent`
/// kept and the lines behind it waiting with it (§3c.4, §3c.5; skep #608);
/// a read that finds its landing keeps it, so the hand-over never sends it
/// twice. Chosen against [`PROBE_CADENCE`]: thirty probes at two seconds
/// hand the line over a minute after its first lost answer where each try
/// fails at once, a timeout adding its own wait to each. Counted per line
/// in memory, as the rider is, so a relaunch counts afresh; the first dial
/// is the person's own call's and counts none.
const MAX_LOST_ANSWERS: u32 = 30;

/// The short wait before a `write_busy` is reissued.
///
/// It is §3c.4's "a silent reissue after a short wait" — interim, open to
/// tuning, as [`PROBE_CADENCE`] is.
const WRITE_BUSY_WAIT: Duration = Duration::from_millis(50);

/// The burst machine's five kinds (§3c.4) — the ops the held store holds.
const BURST_KINDS: [&str; 5] = ["insert", "delete", "copy", "reinstate", "rearrange"];

/// The six non-burst writes §3c.4 names, which a standing hold refuses.
///
/// Each arriving while the board is stopped, poisoned or its writes halted
/// is refused at once with the hold's cause as its token, never held and
/// never dialed ([`Holds::unholdable_refusal`]); `publication.confirm`'s
/// send, the shot's one carrier, takes the same door with `publish` as its
/// op. Every other write outside the five bursts dials as it dials.
pub const UNHOLDABLE_WRITES: [&str; 6] = ["fork", "version", "make_link", "nullify", "edit_link", "publish"];

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
/// person a line whose resends lost their answer ([`MAX_LOST_ANSWERS`]).
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
/// Each is read off a `/changes` row since the hold's `base`: this store's
/// own key, another key with the label this shell's key store holds for it,
/// an unsigned hand under local trust, or a row whose testimony the board
/// lost — the data of the three forms the moved face draws, the strings
/// the copy's.
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

/// The reissues one write has been given so far, and the answers it lost.
///
/// The reissues are what [`classify`] bounds the next by: a `write_busy`
/// reissued once, a `durability` twice, its third holding a burst (§3c.4's
/// rider). Counted by the caller as it reissues ([`Reissues::note`]), so
/// every reissue moves the write toward its bound: a write is dialed four
/// times at most within its call. A held line's lost answers are counted
/// beside them, across its probes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Reissues {
    write_busy: u32,
    durability: u32,
    /// The resends whose answer was lost, across the line's probes.
    ///
    /// Counted by the resend ([`is_lost_answer`]) and read by no
    /// [`classify`]: at [`MAX_LOST_ANSWERS`] the line is the person's. The
    /// person's `send` counts it afresh.
    lost: u32,
}

impl Reissues {
    /// Notes one reissue of `kind` given.
    fn note(&mut self, kind: Reissue) {
        match kind {
            Reissue::WriteBusy => self.write_busy += 1,
            Reissue::Durability => self.durability += 1,
        }
    }
}

/// Classifies a write's outcome by the classification table (§3c.4).
///
/// The outcome, and the reissues the same write has been given, go to
/// exactly one row — the one owner of every reissue's bound.
fn classify(outcome: DialOutcome<'_>, given: Reissues) -> Decision {
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
    /// to the machine"), each keeping its `sent` and its lost answers
    /// counted afresh — the caller hands the board's feed thread its probe,
    /// so the call answers once the lines are handed back, never after a
    /// resend's ack.
    HandedBack,
}

/// A burst admitted: a frame some send of which the board can take.
///
/// It is a frame of [`BURST_KINDS`] and its document — what every held line
/// is made of. Built by [`Burst::admit`] alone, so the hold holds no frame
/// the burst's door did not see.
#[derive(Debug)]
pub struct Burst {
    frame: Value,
    doc: String,
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
        Ok(Burst { frame, doc })
    }

    /// Returns the frame as the page composed it.
    fn frame(&self) -> &Value {
        &self.frame
    }

    /// Returns the burst as a held line stores it (§3c.2).
    ///
    /// It is its document in its one spelling, and its frame with any
    /// `attest` stripped — the resend composes its own when it sends.
    fn into_stored(self) -> (String, Value) {
        let Burst { mut frame, doc } = self;
        if let Some(members) = frame.as_object_mut() {
            members.remove("attest");
        }
        (doc, frame)
    }
}

/// What one dial of a write answered, read once through the table.
#[derive(Debug)]
enum Dialed {
    /// The board's ack.
    Acked(Value),
    /// A hold-class answer, or a refused run.
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
    /// It is an answer the table holds and reissues nowhere, or the shell's
    /// own refusal where the attest could not be composed.
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
    /// `token` and verdict, reissued, or faced — each beside the refusal the
    /// answer is.
    fn refused(decision: Decision, token: &str, verdict: Value, refusal: Refusal) -> Dialed {
        match decision {
            Decision::Hold { cause, sent } => Dialed::Held { reason: Reason::of(cause, sent), refusal },
            Decision::Refused => Dialed::Held { reason: Reason::refused(token, verdict), refusal },
            Decision::Reissue(kind) => Dialed::Reissue { kind, refusal },
            Decision::Neither => Dialed::Faced(refusal),
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
            Unattested::Refused(Refusal::Unreachable(e)) => match classify(DialOutcome::Dial(&e), Reissues::default()) {
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
/// `refused` (a refused run's), `moved` (a moved document's), else
/// `holding` — a line held `head_unreadable` among them, whose refusal says
/// why it waits and which awaits no act of the person's (P10); `sending` is
/// the resend's, never a line's at rest.
fn line_state(reason: &Reason) -> HeldState {
    if reason.cause == cause::HEAD_UNREADABLE {
        HeldState::Holding
    } else if reason.refusal.is_some() {
        HeldState::Refused
    } else if reason.cause == cause::MOVED {
        HeldState::Moved
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

/// Returns whether a dial's `reason` is a lost answer.
///
/// It is the table's lost-answer row (§3c.2's `sent`): `unreachable` with
/// `sent`, which a timeout, a garbled answer and the board's
/// `internal_panic` each answer — never a connection never made, whose
/// `sent` is false. It reads the dial's own answer: a held line's reason
/// keeps an earlier dial's `sent` through a resend that never left.
fn is_lost_answer(reason: &Reason) -> bool {
    reason.cause == cause::UNREACHABLE && reason.sent
}

/// Why a board's directory is not this shell's while another process holds
/// its lock (§3c.3: one shell per data directory).
const ANOTHER_PROCESS: &str = "another process holds this board's held store — one shell per data directory; a second launch hands its address to the running client and exits";

/// The board's `held/<chain>/` (§3c.1) as this shell stands to it.
#[derive(Debug)]
enum Directory {
    /// Not this shell's yet, and why.
    ///
    /// Why: `H.1` not read, the directory or its lock refused, or the lock
    /// held by another process — which the single-instance rule (§3c.3)
    /// leaves only to the instant a second launch's hand-off has not yet
    /// closed, so nothing is kept here as a second shell's. Tried again at a
    /// session's open and at the probe.
    NotYet(String),
    /// This shell's for its life: the directory, and the `flock` on its lock.
    ThisWindow { dir: HeldDir, _lock: File },
}

impl Directory {
    /// Returns the directory `H.1`'s read names (§3c.1).
    ///
    /// It is made `0700` and locked where the board term stands, and not yet
    /// this shell's — why said — where the board serves no `H.1`, whose
    /// chain names the directory, the read, the directory or the lock
    /// refused, or another process holds the lock ([`ANOTHER_PROCESS`]).
    fn of(data_dir: &Path, board_term: Result<Option<BoardTerm>, Halt>) -> Directory {
        let board_term = match board_term {
            Ok(Some(board_term)) => board_term,
            Ok(None) => return Directory::NotYet("the board serves no H.1, whose chain names its held store's directory".to_string()),
            Err(h) => return Directory::NotYet(format!("the board's H.1 could not be read: {h}")),
        };
        let dir = HeldDir::new(data_dir, Chain::from_bytes(board_term.chain));
        match dir.ensure().and_then(|()| dir.try_lock()) {
            Ok(Some(lock)) => Directory::ThisWindow { dir, _lock: lock },
            Ok(None) => Directory::NotYet(ANOTHER_PROCESS.to_string()),
            Err(e) => Directory::NotYet(format!("the held store could not be made or locked: {e}")),
        }
    }
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
    /// yet this shell's ([`Directory::NotYet`]'s why, another process's
    /// lock among the causes), or the file the device refused. The file is
    /// opened at a later touch that finds the queue empty, so no line is
    /// ever renumbered.
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
/// takes (§3c.2) — and the reissues each line's resend has been given and
/// the answers its resends lost, counted across its probes.
#[derive(Debug)]
struct PrincipalHold {
    custody: Custody,
    queue: HeldQueue,
    last_acked: HashMap<String, u64>,
    reissues: HashMap<u64, Reissues>,
}

impl PrincipalHold {
    fn new() -> PrincipalHold {
        PrincipalHold { custody: Custody::Unopened, queue: HeldQueue::in_memory(), last_acked: HashMap::new(), reissues: HashMap::new() }
    }

    /// Notes `at`, the position of a write of the principal's on `doc`.
    ///
    /// It is the document's `base` from here where it is past the position
    /// noted there, which stands otherwise (§3c.2). Answers are noted in the
    /// order they are read, not the order the board committed them — a
    /// call's on its connection's thread, a resend's and a landing the
    /// resend's read found on the board's feed thread — so an earlier write
    /// read after a later one never lowers the base below that later write,
    /// whose row the next hold's read would take for a move (§3c.5).
    fn note_position(&mut self, doc: &str, at: u64) {
        let base = self.last_acked.entry(doc.to_string()).or_insert(at);
        *base = (*base).max(at);
    }

    /// Returns how many lines stand on `doc`.
    fn count(&self, doc: &str) -> u64 {
        self.queue.lines().iter().filter(|l| l.doc == doc).count() as u64
    }
}

/// One board's hold.
///
/// It holds its directory, the three states that hold every burst before
/// any dial — and refuse the six unholdable writes at once — and each
/// principal's queue.
#[derive(Debug)]
struct BoardHold {
    directory: Directory,
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
                let hold = BoardHold { directory: Directory::NotYet("no session has opened at this board yet".to_string()), writes_halted: false, poisoned: false, node_stopped: false, principals: HashMap::new() };
                (entry.reference.clone(), BoardSlot { board: Arc::clone(&entry.board), hold: Mutex::new(hold), draining: AtomicBool::new(false) })
            })
            .collect();
        Arc::new(Holds { sessions, bus, key_store, data_dir, talk, boards })
    }

    /// Says `line` on `Talk` as the hold's: `held: ` and the line.
    fn say(&self, line: impl fmt::Display) {
        (self.talk)(&format!("held: {line}"));
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
        self.establish(slot);
        // A halted file is answered at the principal's next act.
        let _ = self.principal_hold(&mut slot.lock(), session);
    }

    /// Establishes the board's directory where it is not yet.
    ///
    /// `H.1` is read outside the lock (the board keeps the term once found),
    /// the directory then made and locked under it. A hold never comes here:
    /// it never dials to learn where to write.
    fn establish(&self, slot: &BoardSlot) {
        if !matches!(slot.lock().directory, Directory::NotYet(_)) {
            return;
        }
        let board_term = slot.board.board_term();
        let mut board_hold = slot.lock();
        if matches!(board_hold.directory, Directory::NotYet(_)) {
            board_hold.directory = Directory::of(&self.data_dir, board_term);
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
        let ph = principals.entry(principal).or_insert_with(PrincipalHold::new);
        if !ph.custody.settled() && ph.queue.lines().is_empty() {
            match directory {
                Directory::ThisWindow { dir, .. } => match dir.open_file(principal, session.facts.account.as_deref().unwrap_or("")) {
                    Ok(Opened::Live { queue, aside }) => {
                        if let Some(aside) = aside {
                            self.say(format_args!("principal {principal}'s held file named another board or principal, and is set aside at {}", aside.display()));
                        }
                        // A crash's tail, said once as the open's own landing;
                        // the next line written cuts it.
                        match queue.torn() {
                            Some(Torn::Header { bytes }) => self.say(format_args!(
                                "principal {principal}'s held file holds no whole header line ({bytes} bytes of a torn one — a crash before its header's sync) and is read as fresh; the next line written cuts it and heads the file"
                            )),
                            Some(Torn::Line { bytes }) => self.say(format_args!(
                                "principal {principal}'s held file ends in a torn line of {bytes} bytes — a crash's, held by no one — which the next line written cuts off"
                            )),
                            None => {}
                        }
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
    /// held (`send_burst`); one of the six unholdable writes
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
    pub fn send(&self, session: &SessionEntry, frame: Value) -> OpAnswer {
        if is_burst(&frame) {
            return self.send_burst(session, frame);
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
    /// `op` is the write's kind. Where it is one of the six
    /// ([`UNHOLDABLE_WRITES`]) and a hold stands at the board — the own node
    /// stopped, the write path poisoned, the writes halted, in that order —
    /// the write is refused at once under the cause's own name
    /// (`Name::STOPPED`, `Name::POISONED`, `Name::HALTED`), its detail the
    /// `op`, never held and never dialed; `None` where no hold stands or the
    /// kind is not of the six, the write then dialing as it dials — a board
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
    /// anything else faced at the act.
    fn send_burst(&self, session: &SessionEntry, frame: Value) -> OpAnswer {
        let burst = match Burst::admit(frame, session) {
            Ok(burst) => burst,
            Err(refusal) => return OpAnswer::Answered(Err(refusal)),
        };
        {
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
            let line_stands = match self.principal_hold(&mut board_hold, session) {
                Ok(ph) => !ph.queue.lines().is_empty(),
                Err(refusal) => return OpAnswer::Answered(Err(refusal)),
            };
            let hold_cause = standing.or(line_stands.then_some(cause::BEHIND));
            if let Some(cause) = hold_cause {
                return OpAnswer::Answered(self.hold_line(&mut board_hold, session, burst, Reason::of(cause, false)));
            }
        }
        match self.dial_within_call(session, burst.frame()) {
            Dialed::Acked(ack) => {
                self.note_ack(session, burst.frame(), &ack);
                OpAnswer::Answered(Ok(ack))
            }
            Dialed::Held { reason, .. } => OpAnswer::Answered(self.hold(session, burst, reason)),
            Dialed::Reissue { refusal, .. } | Dialed::Faced(refusal) => OpAnswer::Answered(Err(refusal)),
            Dialed::Died => OpAnswer::Died,
        }
    }

    /// Dials one write within its call (§4b.1's `op` row).
    ///
    /// Reissue-class answers are "reissued by the shell and reach the page as
    /// the ack or the next refusal": `frame` attested once where an attest is
    /// owed ([`Holds::attest_where_owed`]), then dialed, a reissue-class
    /// answer reissued as [`classify`] bounds it — a `write_busy` once after
    /// [`WRITE_BUSY_WAIT`], a first and second `durability` as-is — and the
    /// first other answer returned: never a reissue, so its caller meets the
    /// ack or the next refusal.
    fn dial_within_call(&self, session: &SessionEntry, frame: &Value) -> Dialed {
        let frame = match self.attest_where_owed(session, frame) {
            Ok(frame) => frame,
            Err(why) => return Dialed::from(why),
        };
        let mut given = Reissues::default();
        loop {
            match self.dial(session, &frame, given) {
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
    /// `held` answer ([`Holds::hold_line`]).
    ///
    /// # Errors
    ///
    /// Returns `store_halted` where P38 halted the file, and `held_full`
    /// where the principal's queue is full ([`Holds::hold_line`]).
    pub fn hold(&self, session: &SessionEntry, burst: Burst, reason: Reason) -> Result<Value, Refusal> {
        self.hold_line(&mut self.lock(&session.board_reference), session, burst, reason)
    }

    /// Enters one line in the principal's queue at the session's board.
    ///
    /// `board_hold` is that board's hold. The line is the burst as stored,
    /// its frame carrying no attest, copied to its file where it has one,
    /// its `base` the position of the principal's latest write on the document
    /// that the shell knows — its ack's, or the landing the resend's read
    /// found — or else the session's open position (§3c.2); the `held` event
    /// is emitted, and the answer is `{resp: held, held: <k>, cause}`, and
    /// `unwritable` beside it — why — where the device refused its copy or
    /// the file is out of reach, another process's lock on the board's
    /// directory among the causes (§3c.3).
    ///
    /// # Errors
    ///
    /// Returns `store_halted` where the principal's file is halted
    /// ([`Holds::principal_hold`]), and `held_full` where the principal's
    /// queue holds its budget already (`held::MAX_HELD_FRAME_BYTES`'s bytes,
    /// or `held::MAX_HELD_LINES`'s lines) or its ordinals are spent, and
    /// nothing held.
    fn hold_line(&self, board_hold: &mut BoardHold, session: &SessionEntry, burst: Burst, reason: Reason) -> Result<Value, Refusal> {
        let ph = self.principal_hold(board_hold, session)?;
        let (doc, frame) = burst.into_stored();
        let id = frame["id"].as_str().map(str::to_owned);
        let base = ph.last_acked.get(&doc).copied().unwrap_or(session.opened_at);
        let state = line_state(&reason);
        let said = reason.cause.clone();
        let entered = ph.queue.hold(&doc, id.as_deref(), base, frame, reason).map_err(queue_refused)?;
        let unwritable = match &ph.custody {
            Custody::Unwritable(why) => Some(why.clone()),
            _ => entered.unwritten.map(|e| e.to_string()),
        };
        let mut answer = json!({"resp": "held", "held": entered.k, "cause": said});
        if let Some(why) = unwritable {
            answer["unwritable"] = Value::from(why);
        }
        // `emit_held` touches the bus alone, so it is safe under the board's
        // lock.
        self.emit_held(session, &doc, ph.count(&doc), state, Some(&said), &[]);
        Ok(answer)
    }

    /// Notes an acked session write (§3c.2).
    ///
    /// Its `at` becomes the `base` of the next hold on every document its row
    /// names where it is past the position noted there, which stands otherwise
    /// ([`PrincipalHold::note_position`]) — whatever its kind, a burst's, a
    /// mint's or a link's, the first dial's and the resend's alike, each
    /// noted where its answer is read. A read, or a refusal, notes nothing.
    fn note_ack(&self, session: &SessionEntry, frame: &Value, ack: &Value) {
        let Some(at) = acked_at(ack) else { return };
        let docs = written_docs(frame, ack);
        if docs.is_empty() {
            return;
        }
        let mut board_hold = self.lock(&session.board_reference);
        let ph = board_hold.principals.entry(session.facts.principal).or_insert_with(PrincipalHold::new);
        for doc in docs {
            ph.note_position(doc, at);
        }
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
    /// document's waiting lines `behind`, each keeping its `sent` and its lost
    /// answers counted afresh, handing them back to the automatic machine,
    /// and answers at once ([`Resolved::HandedBack`]): the probe that resends
    /// them is the caller's to hand the board's feed thread.
    ///
    /// # Errors
    ///
    /// Its refusals come in this order, the first that holds answering:
    /// `store_halted` where P38 halted the principal's file; `no_such_held`
    /// where no line of ordinal `k` stands; `not_resolvable` where the line
    /// awaits no act of the person's (P10).
    pub fn resolve(&self, session: &SessionEntry, k: u64, act: ResolveAct) -> Result<Resolved, Refusal> {
        let mut board_hold = self.lock(&session.board_reference);
        let ph = self.principal_hold(&mut board_hold, session)?;
        let Some(line) = ph.queue.lines().iter().find(|l| l.k == k) else { return Err(Refusal::shell(Name::NO_SUCH_HELD, json!({"held": k}))) };
        // A line awaiting the person's act alone takes one (P10).
        if !awaits_act(line) {
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
                // before it is sent again (§3c.5) — their lost answers counted
                // afresh, the read run at the next probe, and the refusal
                // faced again where it recurs.
                let waiting: Vec<(u64, bool)> = ph.queue.lines().iter().filter(|l| l.doc == doc && awaits_act(l)).map(|l| (l.k, l.reason.sent)).collect();
                for (k, sent) in waiting {
                    self.remark_line(ph, k, Reason::of(cause::BEHIND, sent));
                    if let Some(given) = ph.reissues.get_mut(&k) {
                        given.lost = 0;
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
    fn dial(&self, session: &SessionEntry, frame: &AttestedWhereOwed<'_>, given: Reissues) -> Dialed {
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
    /// It serves a hold that recurs, a refused run, a moved re-facing; a copy
    /// refused, by the device or past the file's re-mark budget, is said on
    /// `Talk`.
    fn remark_line(&self, ph: &mut PrincipalHold, k: u64, reason: Reason) {
        if let Err(e) = ph.queue.remark(k, reason) {
            self.say(format_args!("line {k}'s new cause could not be written ({e}); a reopen reads its earlier one"));
        }
    }

    /// Takes one line out of the queue, whatever the disk did.
    ///
    /// A `done` the device refused is said on `Talk`, and so is a held
    /// file the volume would not remove once every line in it was done —
    /// the store appends on to it.
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
    }

    /// Emits the `held` event (§4b.2) at the session's board.
    ///
    /// It is `{board, session, doc, held, state, cause?, hands?}`, under the
    /// session the change was made for — `hands` with the `moved` state
    /// alone, the hands whose rows moved the document (§3c.5), each once.
    fn emit_held(&self, session: &SessionEntry, doc: &str, held: u64, state: HeldState, cause: Option<&str>, hands: &[Hand]) {
        let mut data = json!({"board": session.board_reference, "session": session.reference, "doc": doc, "held": held, "state": state.as_str()});
        if let Some(c) = cause {
            data["cause"] = Value::from(c);
        }
        if !hands.is_empty() {
            data["hands"] = Value::Array(hands.iter().map(Hand::json).collect());
        }
        self.bus.emit(EventName::Held, data);
    }

    /// Returns the hands of `rows` — the `/changes` rows since a hold's `base`
    /// the resend's read holds — each once (§3c.5; §4b.2).
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
/// It holds the line's members save `id`, `refusal` beside a refused run's.
fn line_json(l: &HeldLine) -> Value {
    let mut line = json!({"held": l.k, "doc": l.doc, "base": l.base, "frame": l.frame, "cause": l.reason.cause, "sent": l.reason.sent, "time": l.time});
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
        Some("create_new_document" | "fork" | "version" | "publish") => return ack["addr"].as_str().into_iter().collect(),
        Some("make_link" | "emit" | "nullify" | "assert_sup") => &["home"],
        Some("edit_link") => &["d_s", "d_a"],
        _ => &["doc"],
    };
    members.iter().filter_map(|m| frame[*m].as_str()).collect()
}

#[cfg(test)]
mod tests;
