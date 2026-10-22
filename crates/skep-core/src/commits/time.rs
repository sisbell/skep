//! The time writer: the hourly `skep-time` record, and the hour a position
//! is answered from it.
//!
//! It is the board's own daemon writing the time document `T` =
//! `1.1.0.1.0.4` ([`time_document`]) as a new published version per record,
//! in-process as the system account's principal ([`SYSTEM_PRINCIPAL`]) with
//! no session, on the write path's cadence — the sparse anchor the
//! permanence record's D3 (c) names, a record of its own and never a member
//! of the head (the owner's "b", 2026-10-22): two heads of one board at one
//! position stay byte-identical, and the clock rides a document beside `H`.
//!
//! **What a record is.** One `skep-time` record (DOCTRINE D13: one JSON
//! object naming its type) — `type`, `position`, `time`, in that order, no
//! whitespace, unsigned — whose `position` is the kernel's committed head
//! read off one snapshot before the record's own write opens, and whose
//! `time` is the daemon's clock at the write, unix milliseconds, clamped
//! monotone against the record before it: the feed's own reading
//! ([`wall_clock_millis`]), the one the feed stamps each commit's `time`
//! with, so the anchor at or below a position never stands above the line
//! it stands in for. The schema is [`TimeRecord`]'s, on one card.
//!
//! **How it lands.** Per record, two commits — a third where the time
//! document is minted first, and the staging draft ahead of that where none
//! is held — under the same serialization lock the triggering write holds,
//! each through the head writer's door and its helpers
//! ([`HeadWriter::ensure_draft`](super::head::HeadWriter::ensure_draft), [`HeadWriter::commit_insert`](super::head::HeadWriter::commit_insert),
//! [`HeadWriter::commit_publish`](super::head::HeadWriter::commit_publish), [`HeadWriter::run_commit`](super::head::HeadWriter::run_commit)) with testimony
//! [`SYSTEM_TESTIMONY`]: one `insert` of the record atom into the staging
//! draft `1.1.0.1.0.3` the head writer and the registry seed share, then one
//! `publish` shot minting the next member of `T`'s trunk chain — `base` =
//! `T`'s current trunk head with its extent set to that member's full
//! content count, so nothing is carried and each member holds exactly its
//! own record — exactly as a head lands in `H`. `T` is minted published by
//! the first record's write, doc 4 of the system account by the chain's
//! frontier (the draft stands at doc 3 first, whichever writer minted it),
//! and found registered at every later open ([`find_time_document`]).
//!
//! **The cadence**, on the write path with no clock thread — evaluated after
//! every write the write path's session door runs ([`TimeWriter::take_turn`],
//! reached from `commit_under` after the head writer's turn): a record is due
//! by one trigger alone, the head's (c) — an hour ([`TIME_BOUND_MILLIS`]) has
//! passed on the head writer's clock since the last record AND the position
//! moved past the one the last record named. Never on a peer's request;
//! never while the position stands still; never twice for one position (the
//! record's own commits ride the head writer's door, which gives neither
//! writer a turn, and this writer's look is refreshed past them). The clock
//! is the head writer's own ([`HeadWriter::now_millis`](super::head::HeadWriter::now_millis)) — in production the
//! wall clock, in tests the seam `skepd::Daemon::set_head_writer_clock_millis`
//! fixes — so one seam drives both hours and no test sleeps.
//!
//! **Resume by reading.** At open the writer reads `T`'s latest member — its
//! record is `last`, whose `position` is the "moved" gate's reference and
//! whose `time` is the hour's origin — so a board restarted every few
//! minutes still measures its hour from the record it wrote, never from the
//! open. A board with no record yet measures from the feed's recorded time
//! of its first commit ([`Feed::time_at`] at position 1, the board's birth),
//! else from the open, so a board older than an hour that never held a
//! record writes one at its first write after this build's first open, and
//! a board younger than an hour holds none until its hour.
//!
//! **What a refusal does.** A driver refusal on any of the record's commits
//! — the draft's mint, the document's mint, the record's insert or the
//! shot's publish — is said once per cause on the operator stream
//! ([`TimeRefusedLine`]: the position the record would have named, the
//! commit refused and the cause as the wire renders a rejection), the record
//! skipped for this cycle, the last record and the origin as they were, and
//! the triggering write untouched; the next landed commit retries, the hour
//! standing due. A landing clears the memo, so the next refusal is news
//! again.
//!
//! **The reads.** [`hour_at`] answers the newest record at or below a
//! position off the world — `T`'s members read by position, a binary search
//! over the trunk chain's ordinals, never the feed — for the age read that
//! falls back on it where the feed's line is gone (`Commits::mint_time`).

use parking_lot::Mutex;
use serde_json::Value;
use skep_address::{ordinal, shift, validate, Address, Nat};
use skep_arrangement::{trunk_head, Base, HasM5, Run, Shot, ShotRun, VPos};
use skep_content::{HasContent, Val};
use skep_engine::{EngineStores, World};
use skep_febe::{lower_txn, Op, OpKind, Stores};
use skep_namespace::{
    first_version_address, system_account, time_document, HasM3, SYSTEM_PRINCIPAL,
};
use skep_util::notice::Class;

use super::feed::Feed;
use super::head::{Refused, SYSTEM_TESTIMONY, TIME_BOUND_MILLIS};
use super::sidecar::wall_clock_millis;
use super::{write_meta, Commits, Lines};
use crate::codec::op_name;
use crate::serial::SerialGuard;

/// The time record's `type` member.
///
/// It is one spelling for the writer and the readers that parse it back.
const RECORD_TYPE: &str = "skep-time";

/// One `skep-time` record (wire.md §The other endpoints, the time document).
///
/// It is the schema on one card, rendered in the schema's order and read
/// back by the same card: `type` is a constant of the schema and not a
/// field, and [`TimeRecord::parse`] refuses a body that carries another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TimeRecord {
    /// The committed head the record names, read before its own write opens.
    pub(super) position: u64,
    /// The daemon's clock at the write, unix milliseconds, monotone.
    pub(super) time: u64,
}

impl TimeRecord {
    /// Returns the record's bytes, hand-marshaled in schema order.
    ///
    /// The order is `type`, `position`, `time`, with no whitespace — not the
    /// codec's sorted-key marshal, which would reorder them. One literal, so
    /// the schema's order is read off the literal itself.
    fn to_bytes(&self) -> Vec<u8> {
        format!(r#"{{"type":"{RECORD_TYPE}","position":{},"time":{}}}"#, self.position, self.time)
            .into_bytes()
    }

    /// Reads back whole a record this build wrote.
    ///
    /// It answers `None` for bytes that are not JSON, that carry another
    /// `type`, or a member missing or malformed; a member it does not read
    /// goes unchecked. The inverse of [`TimeRecord::to_bytes`].
    fn parse(bytes: &[u8]) -> Option<TimeRecord> {
        let v: Value = serde_json::from_slice(bytes).ok()?;
        if v.get("type")?.as_str()? != RECORD_TYPE {
            return None;
        }
        Some(TimeRecord { position: v.get("position")?.as_u64()?, time: v.get("time")?.as_u64()? })
    }
}

/// The writer's mutable state.
///
/// It is everything the trigger reads and a landing updates. Behind a
/// [`Mutex`], but never held across a commit: the decision is taken under it
/// and it is dropped before any write, as the head writer's is.
struct TimeState {
    /// The record the most recent landing published; `None` before the first.
    ///
    /// Read off `T` at open, set by each landing, never reset by a restart:
    /// "the position moved" reads its `position`, and the next record's
    /// `time` is clamped against its `time`.
    last: Option<TimeRecord>,
    /// The clock reading at the last record, on the head writer's clock:
    /// the hour's origin.
    ///
    /// Resumed at open from the last record's own `time`, else from the
    /// feed's recorded time of the board's first commit, else from the open
    /// (the module doc's resume by reading).
    last_time_millis: u64,
    /// The kernel's committed seq as of the writer's last look.
    ///
    /// The look is at open, at each evaluation, and after the record's own
    /// commits, so a write that landed nothing is told from a commit.
    last_seen_position: u64,
    /// The time document, found at open or minted at the first record.
    time_document: Option<Address>,
    /// The memo of the last refusal said: the commit refused and its cause.
    ///
    /// A refusal at the same commit rendering the same is not said again
    /// while it stands; cleared when a record lands.
    last_refusal: Option<(&'static str, String)>,
}

/// The time writer, owned by [`Commits`] beside the head writer.
///
/// It holds its own handle on the engine's one kernel (an [`EngineStores`]
/// clone — the same `Arc<Kernel>`), the mutable state, and the classed door
/// its one line goes through; the clock it measures by is the head
/// writer's, reached at each turn.
pub(super) struct TimeWriter {
    stores: EngineStores,
    state: Mutex<TimeState>,
    lines: Lines,
}

impl TimeWriter {
    /// Opens the writer over `stores`, resuming by reading `T` and the feed.
    ///
    /// It reads `T`'s latest member off one snapshot — the record it holds
    /// becomes `last` whole, so a record written after a restart names no
    /// position already dated, and the hour is measured from the record's
    /// own `time` — and the time document where an earlier uptime minted it.
    /// With no record, the hour's origin is the feed's recorded time at
    /// position 1, the board's first commit, else the open (the module doc's
    /// resume by reading). `lines` is the write path's classed door, cloned
    /// in, for the one line this writer says.
    pub(super) fn open(stores: EngineStores, feed: &Feed, lines: &Lines) -> TimeWriter {
        let snap = stores.kernel().snapshot();
        let last = read_latest_record(snap.world());
        let time_document = find_time_document(snap.world());
        let last_time_millis = match last {
            Some(record) => record.time,
            None => feed.time_at(1).unwrap_or_else(wall_clock_millis),
        };
        TimeWriter {
            stores,
            state: Mutex::new(TimeState {
                last,
                last_time_millis,
                last_seen_position: snap.seq().0,
                time_document,
                last_refusal: None,
            }),
            lines: lines.clone(),
        }
    }

    /// Takes the time writer's turn, under the caller's serialization guard.
    ///
    /// It is taken from [`Commits::commit_under`] after every write that door
    /// runs, after the head writer's turn: if a commit landed (the kernel's
    /// seq, never the answer, is the arbiter), and the position moved past
    /// the last record's, and an hour has passed on the head writer's clock
    /// since that record, write one. The record's own commits go through
    /// [`Commits::commit_recorded`], which gives neither writer a turn; the
    /// look at the end keeps them from reading as a later write's landing,
    /// and the head writer is told the same ([`HeadWriter::mark_own_commits_seen`](super::head::HeadWriter::mark_own_commits_seen)).
    pub(super) fn take_turn(&self, wp: &Commits, serial: &SerialGuard<'_>) {
        let due = {
            let mut state = self.state.lock();
            let snap = self.stores.kernel().snapshot();
            let position = snap.seq().0;
            // Landed, not merely answered: unmoved past the last look,
            // nothing to evaluate.
            if position <= state.last_seen_position {
                return;
            }
            state.last_seen_position = position;
            // Never twice for one position, and never while it stands still.
            let moved = state.last.map_or(position > 0, |r| position > r.position);
            if !moved {
                return;
            }
            // Trigger (c), the head's hour, on the head writer's clock.
            let now = wp.head_writer.now_millis();
            if now.saturating_sub(state.last_time_millis) < TIME_BOUND_MILLIS {
                return;
            }
            (position, now, state.last.map_or(0, |r| r.time))
        };
        let (position, now, last_time) = due;
        // The record's `time` is the writer's clock reading — the wall clock
        // in production, the one reading the feed stamps each commit's
        // `time` with; the seam's in a test — clamped monotone against the
        // record before it.
        let record = TimeRecord { position, time: now.max(last_time) };
        let landed = self.write_record(wp, serial, &record);
        let mut state = self.state.lock();
        if landed {
            state.last = Some(record);
            state.last_time_millis = now;
            state.last_refusal = None;
        }
        // The record's own commits moved the seq: the next evaluation
        // measures "landed" from here, as the head writer's does.
        state.last_seen_position = self.stores.kernel().snapshot().seq().0;
        wp.head_writer.mark_own_commits_seen();
    }

    /// Writes one record: the atom into the staging draft, then the shot.
    ///
    /// Its commits are the insert and the publish shot minting the next
    /// member of `T`, the time document's mint ahead of them at the first
    /// record ([`TimeWriter::ensure_document`]) and the staging draft's ahead
    /// of that where none is held ([`HeadWriter::ensure_draft`](super::head::HeadWriter::ensure_draft)). `true` iff
    /// the shot committed — a failed publish leaves the atom an orphan in the
    /// draft, and the next commit retries.
    fn write_record(&self, wp: &Commits, serial: &SerialGuard<'_>, record: &TimeRecord) -> bool {
        let position = record.position;
        let refused =
            |act: &'static str, cause: String| self.say_the_refusal_once(position, act, cause);
        let Some(draft) = wp.head_writer.ensure_draft(wp, serial, &refused) else {
            return false;
        };
        let Some(doc) = self.ensure_document(wp, serial, &refused) else {
            return false;
        };
        let bytes = record.to_bytes();
        let next_ordinal = {
            let snap = self.stores.kernel().snapshot();
            snap.world().m5().content_count(&draft) + Nat::from(1u32)
        };
        let Some(atom_start) = wp.head_writer.commit_insert(
            wp,
            serial,
            &draft,
            next_ordinal,
            vec![Val::new(bytes)],
            &refused,
        ) else {
            return false;
        };
        // The shot: base is T's current trunk head (or T itself while
        // memberless), extent = that member's full content count so nothing
        // is carried — each member holds exactly its own record, as H's do.
        let (base_member, extent) = {
            let snap = self.stores.kernel().snapshot();
            let world = snap.world();
            let member = trunk_head(world.m3(), &doc).unwrap_or_else(|| doc.clone());
            let extent = world.m5().content_count(&member);
            (member, extent)
        };
        let run = match Run::new(atom_start, Nat::from(1u32)) {
            Ok(run) => run,
            Err(e) => {
                // Unreachable — the insert answered a content element start —
                // and named rather than silent (I11 (c)).
                self.say_the_refusal_once(
                    position,
                    op_name(OpKind::Publish),
                    format!("its atom's run is malformed: {e}"),
                );
                return false;
            }
        };
        let shot = Shot {
            base: Some(Base { member: base_member, extent }),
            draft: Some(draft.clone()),
            runs: vec![ShotRun { origin: draft, run }],
        };
        wp.head_writer.commit_publish(wp, serial, doc, shot, &refused).is_some()
    }

    /// Returns the time document, minting it now where none is held.
    ///
    /// It is the one found at open or minted by an earlier record this
    /// uptime, else minted now under the system account, born published —
    /// once for the life of the board where the mint lands at
    /// [`time_document`], since every later open finds it there. The staging
    /// draft is minted ahead of it by whichever writer first needed it, so
    /// the mint lands at doc 4 by the chain's frontier; a mint that lands
    /// elsewhere is said ([`DocumentMintedElsewhere`]) and the record goes on
    /// with the document minted. A refusal of the mint is `refused`'s to say.
    fn ensure_document(
        &self,
        wp: &Commits,
        serial: &SerialGuard<'_>,
        refused: Refused<'_>,
    ) -> Option<Address> {
        // Read in a statement of its own, so the state guard drops at the
        // `;`: this lock is never to be held across a commit.
        let found = self.state.lock().time_document.clone();
        if found.is_some() {
            return found;
        }
        let account = system_account();
        let op = Op::CreateNewDocument { account: account.clone(), published: Some(true) };
        let meta = write_meta(&op)?.attributed(SYSTEM_TESTIMONY.to_string(), None);
        let stores = &self.stores;
        let doc = wp.head_writer.run_commit(wp, serial, meta, refused, move || {
            stores
                .namespace()
                .create_new_document(SYSTEM_PRINCIPAL, &account, Some(true))
                .map_err(|e| lower_txn(OpKind::CreateNewDocument, e))
        })?;
        if doc != time_document() {
            self.lines.say(
                Class::Failure,
                DocumentMintedElsewhere { minted: &doc, expected: &time_document() },
            );
        }
        self.state.lock().time_document = Some(doc.clone());
        Some(doc)
    }

    /// Says the refusal line, once per commit and cause.
    ///
    /// `act` is the op of the record's commit the refusal was met at, as the
    /// wire names it, and `cause` the refusal as the wire renders a
    /// rejection. Compared under the state lock with the last one said: the
    /// same commit and cause is not said again while it stands; a landing
    /// clears the memo.
    fn say_the_refusal_once(&self, position: u64, act: &'static str, cause: String) {
        let mut state = self.state.lock();
        if state.last_refusal.as_ref().is_some_and(|(a, c)| *a == act && *c == cause) {
            return;
        }
        self.lines.say(Class::Failure, TimeRefusedLine { position, act, cause: &cause });
        state.last_refusal = Some((act, cause));
    }
}

/// The time writer's line: a record the driver refused.
///
/// In the operator stream's words: `time writer: the time record at position
/// {p} was refused at its {op} ({cause}); no record written this cycle` —
/// the position the record would have named, the commit the refusal met
/// (the staging draft's or the time document's `create_new_document`, the
/// record's `insert` or the shot's `publish`) and the cause as the head
/// writer's line renders one. A pure value the unit suite pins by
/// `to_string()`; emitted under `Class::Failure`, once per commit and cause.
struct TimeRefusedLine<'a> {
    position: u64,
    act: &'static str,
    cause: &'a str,
}

impl std::fmt::Display for TimeRefusedLine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "time writer: the time record at position {} was refused at its {} ({}); no record \
             written this cycle",
            self.position, self.act, self.cause
        )
    }
}

/// The time writer's other line: the time document minted elsewhere.
///
/// In the operator stream's words it says the time document minted somewhere
/// other than the address the chain's frontier pins, the cause, and what
/// still serves: the record goes on in the document it minted. A pure value
/// the unit suite pins by `to_string()`; emitted under `Class::Failure`.
struct DocumentMintedElsewhere<'a> {
    minted: &'a Address,
    expected: &'a Address,
}

impl std::fmt::Display for DocumentMintedElsewhere<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "time writer: the time document minted at {}, not at {} — another writer minted \
             under the system account; the records go on in the document it minted",
            self.minted, self.expected
        )
    }
}

/// Returns `T`'s latest member's record: the resume by reading.
///
/// `None` while `T` is unregistered or its trunk chain has no member, or
/// its newest member holds no record this build reads — treated as no
/// record, so the next hour writes a fresh one.
fn read_latest_record(world: &World) -> Option<TimeRecord> {
    let member = trunk_head(world.m3(), &time_document())?;
    read_record_member(world, &member)
}

/// Returns the record one member of `T` holds.
///
/// It is the member's atom at content position 1, parsed as this build
/// writes it.
fn read_record_member(world: &World, member: &Address) -> Option<TimeRecord> {
    let i_addr = world.m5().point(member, &VPos::content(Nat::from(1u32)))?;
    TimeRecord::parse(world.content().value_at(i_addr.tumbler())?.as_bytes())
}

/// Returns the time document an earlier uptime minted, if any.
///
/// It is [`time_document`] when that is a registered, published document —
/// the only shape this writer ever gives it — else `None`, and the first
/// record mints it.
fn find_time_document(world: &World) -> Option<Address> {
    let doc = time_document();
    let m3 = world.m3();
    (m3.is_registered_document(&doc) && m3.published(&doc)).then_some(doc)
}

/// Returns the hour of `position`: the newest time record at or below it.
///
/// It is the anchor's answer for a minted address's age where the feed's
/// line is gone — the record's `time`, within an hour below the position's
/// own time while the board was being written, and further below it across
/// an idle stretch, since a record lands at the first write an hour or more
/// after the last — read off `world` alone: `T`'s members by position, a
/// binary search over the trunk chain's ordinals from `T.1` to its head,
/// each probe one point read of the member's atom, so order log₂(the
/// records) reads and never the feed. `None` where no record stands at or
/// below `position`: a board younger than an hour, a position below the
/// first record, or a member whose record this build does not read.
pub(super) fn hour_at(world: &World, position: u64) -> Option<u64> {
    let doc = time_document();
    let head = trunk_head(world.m3(), &doc)?;
    let first = first_version_address(&doc)?;
    let count = u64::try_from(ordinal(head.tumbler())).ok()?;
    let member_k = |k: u64| -> Option<Address> {
        validate(shift(first.tumbler(), &Nat::from(usize::try_from(k - 1).ok()?))).ok()
    };
    // The largest k whose record names a position at or below `position`:
    // records' positions rise with k (never twice for one position), so the
    // answer is a prefix of the ordinals.
    let (mut lo, mut hi) = (1u64, count);
    let mut found: Option<u64> = None;
    while lo <= hi {
        let mid = lo + (hi - lo) / 2;
        let record = read_record_member(world, &member_k(mid)?)?;
        if record.position <= position {
            found = Some(record.time);
            lo = mid + 1;
        } else {
            if mid == 1 {
                break;
            }
            hi = mid - 1;
        }
    }
    found
}

#[cfg(test)]
mod tests;
