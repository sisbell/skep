//! The published head writer (PUB-6.65, RES-304).
//!
//! It is the board's own daemon writing the head document `H` =
//! `1.1.0.1.0.2` as a new published version per head, in-process as the
//! system account's principal ([`SYSTEM_PRINCIPAL`]) with no session, on the
//! write path's cadence.
//!
//! **What a head is.** One `skep-head` record — `type`, `format`, `position`,
//! `chain`, `base`, `prev`, in that schema order, no whitespace, unsigned —
//! whose `(position, chain)` is the kernel's committed pair read off one
//! [`Snapshot`](skep_kernel::Snapshot) before the head's own write opens (the
//! value `/health` serves; read here off the kernel directly, not through
//! febe). A head names a coordinate strictly below its own commit and never
//! its own commit — no bytes can carry their own hash — so consecutive heads
//! are chained through the journal's own chain by construction, `prev` being
//! navigation (PUB-6.65's recursion rule). `/health` is the live pair, `H` the
//! durable record. The schema is [`HeadRecord`]'s, on one card.
//!
//! **How it lands.** Per head, two commits — three where the staging draft is
//! minted first — under the same serialization lock the triggering write
//! holds, each through the head writer's door ([`Commits::commit_recorded`])
//! with testimony [`SYSTEM_TESTIMONY`]: (1) one `insert` of the head record
//! atom into a private staging draft (minted once under the system account,
//! `published: false`, and reused — across restarts too: it is
//! [`staging_draft_address`], doc 3 of the system account, the one document
//! the system principal ever mints, and a reopened writer finds it registered
//! rather than minting another; the head reaches `H` and that draft and no
//! other document), then (2) one `publish` shot minting the next member of
//! `H`'s trunk chain — `base` = `H`'s current trunk head with its extent set
//! to that member's full content count (so nothing is carried and each member
//! holds exactly its own record; 0 at the first head, written while `H` is
//! memberless), `draft` = the staging draft, `runs` = the new atom's one run.
//! The shot's source consult runs at
//! `visible_to(Caller::Principal(SYSTEM_PRINCIPAL))`, never System's — the
//! system principal owns `H` and the draft, so it never withholds.
//!
//! **The cadence**, on the write path with no clock thread — evaluated after
//! every write the write path's session door runs ([`HeadWriter::take_turn`],
//! reached from `commit_under`): a head is due when (a) ≥ [`COUNT_BOUND`]
//! commits that are not the writer's own have landed since the last head, or
//! (b) the newest retained checkpoint is not the one the last head named as
//! its `base`, or (c) ≥ [`TIME_BOUND_MILLIS`] have elapsed since the last
//! head and the position moved. Never on a peer's request; never while the
//! position has not moved; never twice for one position (the head's own
//! commits ride the head writer's door, which gives the head writer no turn,
//! so they are neither counted nor able to re-trigger). Landed, not merely
//! acked: the turn is taken after every write `commit_under` runs — an ack
//! that committed nothing this call (an idempotency replay answered from
//! M10's memo, `emit`'s incumbent ack) and a refusal included; the kernel's
//! seq, not the answer, says whether a commit landed, and one that did not
//! counts nothing and evaluates no trigger.
//!
//! **The first head is the claim's** (signed ops). The cadence above governs
//! every head after the first. `H.1` is written in the claim's own serialized
//! step — [`HeadWriter::write_first_head`], reached from the daemon's
//! claim-flip tail under the same guard the claim committed under, before any
//! later write is admitted — naming the claim's own position, so a claimed
//! board takes attested writes, whose entry frame names the board by `H.1`'s
//! pair (signed-ops D13), from the claim on and not after the cadence's first
//! 64 commits, checkpoint or hour. Where the cadence already wrote a head
//! before or at the claim, the claim writes none: writing the first head is a
//! no-op on a board with a head, so the claim writes one head, never a
//! second. The claim and `H.1` are two transactions, and a daemon that opens
//! a claimed board whose journal holds no head writes `H.1` before it serves,
//! through the same call (skepd's `server.rs`, the open). A refused `H.1` is
//! surfaced like any refused head (below) and the claim stands, the head
//! owed: the "claimed, no head" test runs at every turn of the write path
//! from then on — a refused write's turn included,
//! [`Commits::take_turn_after_refusal`] — ahead of the landed-commit
//! triggers, so the next turn writes it (the claim's head, owed, below).
//!
//! **Resume by reading.** At open the writer reads `H`'s latest member — its
//! `position` and `chain` (the next head's `prev`; a head is owed only once
//! the position moves past it) and its `base` (trigger (b)'s reference: a
//! checkpoint taken after that head, before or after a restart, is named by
//! the next head's `base`) — and finds the staging draft where it left it; a
//! crash between the insert and the shot leaves an orphan atom in the draft
//! and no member, and the next head's shot names the newer atom (PUB-2.26's
//! no-residue).
//!
//! **Resume from the feed.** The cadence's two counters are resumed at open
//! from the change feed's testimony about the commits landed above the
//! recorded head's position (`Feed::entries_above`) — the count off the
//! kernel's seq instead where the walk's region is pending at open
//! ([`HeadWriter::open`]) — so that PUB-6.65's "64 commits … have landed
//! since the last head" and "one hour has passed since the last head" are
//! true of the board across a restart and not of the process:
//! `commits_since_head` is the count of those entries whose testimony is not
//! `"system"` — a bare entry counts, conservative by at most the head's own
//! commits, so a head fires at most a few commits early and never twice — and
//! the hour's origin is the recorded `time` of the head's own last entry, the
//! last testifying `"system"` (else the first entry above the position
//! carrying a time; else open-time). The clock is therefore the feed's own:
//! [`wall_clock_millis`], the one reading both take. A lost sidecar leaves the
//! count early and never late — the open that finds it lost counts every
//! journal record above the position off the kernel's seq, and an open after
//! the walk has landed counts the bare entries it re-covered, every one above
//! the position, the head's own among them (their testimony gone), which is
//! the "at most the head's own commits" above — and the hour measured from
//! open, the one origin then on record. D1 is kept — a gate reads testimony to
//! decide when, and the head's bytes stay a pure function of the root;
//! AUTH-4.56's rewritable sidecar can move one head's timing within the bounds
//! the triggers already allow, never a duplicate and never a changed content.
//!
//! **What a refusal does.** A driver refusal on any of the head's commits is a
//! surfaced failure (I11 (c), PUB-5.75: never a board left silently
//! headless): row 38's line names it (`operations.md` §1.1 row 38; §4 row 31)
//! — the position the head would have named, the commit refused — the
//! draft's mint, the record's insert or the shot's publish — and the refusal
//! as the wire renders a rejection, its code and its detail through M10's own
//! lowering ([`lower_txn`]), never a store error's `Debug` — said once per
//! cause: a memo of the last refusal said, its commit and its cause, is kept
//! under the state lock, a refusal at that commit rendering as that one is
//! not said again (the trigger stays due and every landed commit retries
//! it, so the same cause would otherwise be said per commit), and any other
//! is a new cause and is said. Every refused attempt is counted all the
//! same. The head is skipped for this cycle, the writer's last head and its
//! counters as they were, and the triggering write is untouched — it
//! committed, and its ack is owed whatever the daemon's own write did. When
//! a head next lands the memo clears with one `landing:` line naming the
//! head's position, the attempts refused, the first refused position and
//! how long the refusals lasted ([`RefusalsClearedLine`]), so the next
//! refusal is news again. The next landed commit retries a cadence head,
//! whose trigger stays due.
//!
//! **The claim's head, owed** (SO-I4 (a): the boundary is derived "from the
//! write path's next turn wherever its first write was refused"). The first
//! head no trigger made due: refused, it is owed
//! (`HeadState::first_head_owed`), and "claimed, no head" is tested at every
//! turn — a landed write's, a refused write's
//! ([`Commits::take_turn_after_refusal`]), a replay's — ahead of the
//! landed-commit triggers, until a head lands; where a head already stands
//! the test is a no-op, so it costs an idle turn one look at the state. So a
//! running claimed board whose `H.1` was refused answers attested writes
//! `attestation_invalid:board_unavailable` for exactly one write — the
//! refused writer's own turn writes `H.1`, and its retry is admitted — and
//! not until a trigger it cannot fire, or a restart. The open closes the same
//! window for a board that restarts inside it (skepd's `server.rs`). The
//! daemon opens its kernel `Fsync` only, so a head is never written over an
//! in-memory kernel (whose chain is the zero seed at every coordinate); a
//! poisoned kernel refuses the triggering write first, so no head the
//! cadence makes due is attempted over it — an owed first head is attempted
//! at every turn, and the kernel refuses it too.
//!
//! **Why not `Caller::System`.** That is M9's rule-fire path (PUB-6.28),
//! which mints nothing and carries three registration conditions the head
//! cannot meet. The head writer acts as the genesis-seeded system principal on
//! M3/M5, never constructing `Caller::System`; every ω check passes because
//! the system account owns `H` and its draft, and nothing in the engine is
//! widened.
//!
//! **The door's other users.** The link-type registry's seed (`registry.rs`,
//! this module's sibling) writes the registry document `1.1.0.1.0.1` at every
//! open as the same principal with the same testimony, through the same
//! helpers — [`HeadWriter::ensure_draft`], [`HeadWriter::commit_insert`],
//! [`HeadWriter::commit_publish`] and [`HeadWriter::run_commit`], each
//! `pub(super)` for it — and reuses the one staging draft; and the time
//! writer (`time.rs`, the other sibling) writes the time document
//! `1.1.0.1.0.4` on the write path's cadence through the same helpers, by
//! the same hour bound ([`TIME_BOUND_MILLIS`]) read off this writer's own
//! clock ([`HeadWriter::now_millis`]), so one seam drives both hours. The
//! system principal mints no document but the draft and the time document,
//! whichever writer mints the draft first, and row 40's line is the fence
//! for all three. A refused commit of the seed's or the time writer's is its
//! own to say, so the helpers take who says a refusal ([`Refused`]) rather
//! than row 38's position. The head's own bytes are untouched by the time
//! record: no timestamp rides `H`, so two heads of one board at one
//! position stay byte-identical.

use std::io;
use std::time::Instant;

use parking_lot::Mutex;
use serde_json::Value;
use skep_address::{validate, Address, Nat, Tumbler};
use skep_arrangement::{
    birth_version, trunk_head, Base, Caller, Deposit, HasM5, Run, Shot, ShotRun, VPos,
};
use skep_content::{HasContent, Val};
use skep_engine::{EngineStores, World};
use skep_febe::{lower_txn, Codec, Op, OpKind, Rejection, Response, Stores};
#[cfg(any(test, feature = "test-hooks"))]
use skep_febe::RejectCode;
use skep_identity::BoardTerm;
use skep_kernel::Seq;
use skep_namespace::{head_document, system_account, HasM3, SYSTEM_PRINCIPAL};
use skep_util::json::{hex_string, parse_lower_hex};
use skep_util::notice::Class;

use super::feed::Feed;
use super::sidecar::{wall_clock_millis, CommitMeta};
use super::{write_meta, Lines, WriteMeta, Commits};
use crate::codec::{op_name, JsonCodec};
use crate::serial::SerialGuard;

/// The head record's `format` member: the journal stamp in force (`SKJ4`).
///
/// It names the hash and the byte format the `chain` value was computed
/// under, so a newer daemon reading an older head knows which chain it belongs
/// to. Under `SKJ4` every chain value is SHA-256 over a preimage carrying a
/// per-transaction salt, the chain's salt, so a head naming `SKJ3` belongs to
/// a chain no `SKJ4` board recomputes. An `SKJ3` head and an `SKJ4` head share
/// the schema and every other member's encoding; the stamp alone tells them
/// apart. Derived from the kernel's own stamp, [`skep_kernel::JOURNAL_FORMAT`],
/// by a `const` UTF-8 read, so the next bump of the journal format moves this
/// member by itself and no hand re-key is owed here; the stamp is four ASCII
/// bytes, so the read cannot fail.
const FORMAT_STAMP: &str = match std::str::from_utf8(&skep_kernel::JOURNAL_FORMAT) {
    Ok(stamp) => stamp,
    Err(_) => panic!("the journal format stamp is four ASCII bytes"),
};

/// The head record's `type` member.
///
/// It is one spelling for the writer and the resume that reads it back.
const RECORD_TYPE: &str = "skep-head";

/// The published head's testimony (wire.md §The change feed).
///
/// It is `key`'s third value: what the head writer's own commits record in
/// place of a session's — made in-process as the system account's principal
/// with no session, so no fingerprint and no `"bare"` is true of them. One
/// spelling because the resume reads it back ([`resume_cadence`]) to tell the
/// head's own commits from the ones the cadence counts.
pub(super) const SYSTEM_TESTIMONY: &str = "system";

/// The count bound (PUB-6.65, RES-304): commits since the last head.
///
/// A head is due once this many commits that are not the writer's own have
/// landed since the last head. 64 — at that count the unheld tail a rewrite
/// can hide in is ≤ 64 commits and the heads are ~1/64 of the commits, ~19
/// bytes per user commit amortized (the investigation's §3.3 table).
/// Evaluated on the write path, never by a thread — the posture the kernel's
/// own checkpoint cadence takes, which skepd's `server.rs` configures.
const COUNT_BOUND: u64 = 64;

/// The time bound (PUB-6.65): one hour since the last head.
///
/// A head is also due once this long has passed since the last head and the
/// position has moved, so a slow board's head is renewed by its first commit
/// an hour or more after the last head — evaluated lazily on that commit,
/// never by a thread, and never writing a duplicate for a position that has
/// not moved. The time writer (`time.rs`, this module's sibling) measures
/// its own hour by the same bound, on the same clock, so the two cadences
/// are one hour and one seam.
pub(super) const TIME_BOUND_MILLIS: u64 = 3_600_000; // one hour

/// The test seam's standing detail, for a refusal of the next head.
///
/// It is the `detail` of the refusal
/// `skepd::Daemon::refuse_the_next_head_once` arms, its `_as` sibling arming a
/// detail of the test's own, so a suite can stand two causes against the
/// once-per-cause memo.
#[cfg(any(test, feature = "test-hooks"))]
const SEAM_REFUSAL_DETAIL: &str = "the test seam's refusal";

/// The head writer's own clock, so the time bound is drivable in tests.
///
/// The bound is trigger (c), driven through a seam rather than a `sleep`. In
/// production `now_millis` is [`wall_clock_millis`] — the one reading of the
/// clock the feed stamps each commit's `time` with, so the hour the resume
/// takes from the head's own entry (the module doc's resume from the feed) is
/// measured on the clock that recorded it; a wall clock that steps is
/// tolerated by the trigger's `saturating_sub`, and the cost of a step is one
/// head early or late by the step, never a duplicate. `Clock::set_millis`
/// overrides it with a fixed reading (the test seam, reached through
/// `skepd::Daemon::set_head_writer_clock_millis`), which a test therefore
/// sets relative to the wall clock rather than at small numbers a resumed
/// origin would dwarf.
///
/// Its lock is innermost: [`HeadWriter::take_turn`] reads it under the state
/// lock, and nothing holding it takes another — the reading is copied out in
/// one statement, so the wall-clock read itself runs outside this lock.
struct Clock {
    /// A test's fixed reading, held until changed.
    ///
    /// `None` — the only state production ever sees — reads
    /// [`wall_clock_millis`]. An `Option` and not a sentinel: every `u64` is a
    /// reading a test may fix, `u64::MAX` (the far-future "the hour has
    /// certainly passed") included, and a sentinel drawn from that domain
    /// would read the wall clock for its one value in silence.
    fixed_millis: Mutex<Option<u64>>,
}

impl Clock {
    fn new() -> Clock {
        Clock { fixed_millis: Mutex::new(None) }
    }

    fn now_millis(&self) -> u64 {
        let fixed = *self.fixed_millis.lock();
        fixed.unwrap_or_else(wall_clock_millis)
    }

    #[cfg(any(test, feature = "test-hooks"))]
    fn set_millis(&self, millis: u64) {
        *self.fixed_millis.lock() = Some(millis);
    }
}

/// The writer's mutable state.
///
/// It is everything the trigger reads and the head updates. Behind a
/// [`Mutex`], but never held across a commit: the decision is taken under it
/// and it is dropped before any head write, which takes it again for the
/// staging draft ([`HeadWriter::ensure_draft`]); `parking_lot`'s lock is not
/// re-entrant, so holding it across the write would deadlock the write on
/// itself.
struct HeadState {
    /// The record the most recent head published; `None` before the first ever.
    ///
    /// It is read off `H` at open — `None` too where `H`'s latest member
    /// holds no record this build reads ([`read_latest_head`]) — set by each
    /// head that lands, never reset by a restart. Every reference the cadence
    /// takes to what the last head named is a reading of this one value: "the
    /// position moved" and "never twice for one position" read its
    /// `position`, the next head's `prev` is its [`HeadRecord::pair`], and
    /// trigger (b)'s reference is its `base` — the checkpoint the last head
    /// named — so a checkpoint that landed after it is named by the next
    /// head's `base`, whichever side of a restart the last one was written on.
    last_head: Option<HeadRecord>,
    /// The kernel's committed seq as of the writer's last look.
    ///
    /// The look is at open, at each evaluation, and after the head's own
    /// commits — so a write that landed nothing (a refusal, an idempotency
    /// replay, an incumbent ack) is told from a commit: the seq did not pass
    /// this.
    last_seen_position: u64,
    /// Trigger (a)'s count: commits not the writer's own since the last head.
    ///
    /// Resumed at open from the feed's entries above the last head's position
    /// (the module doc's resume from the feed), so a board restarted every few
    /// commits still reaches [`COUNT_BOUND`]; where the sidecar was lost or
    /// torn and its region is pending at open, resumed off the kernel's seq
    /// instead — every record above the head's position counts, the head's
    /// own and the records within a commit among them — early by at most
    /// those, never late ([`HeadWriter::open`]).
    commits_since_head: u64,
    /// The clock reading at the last head: trigger (c)'s base.
    ///
    /// It is in [`wall_clock_millis`]'s domain. Resumed at open from the last
    /// head's own recorded `time` in the feed (resume from the feed), so after
    /// a reopen the hour is measured from the last head the board wrote and
    /// not from this open; the head itself carries no timestamp (two heads of
    /// one board at one position are byte-identical), so a bare or absent
    /// sidecar leaves this at open-time, the one origin then on record.
    last_head_millis: u64,
    /// The staging draft, found at open or minted at first need.
    ///
    /// It is [`staging_draft_address`] once it is registered — or, where the
    /// mint landed elsewhere (row 40), the draft minted; `None` only on a
    /// board that has never written a head.
    staging_draft: Option<Address>,
    /// The claim's head, owed (the module doc's section).
    ///
    /// Set where a first head — the claim's step's, or the open's — did not
    /// land, refused by the driver or by a halted write path's door; cleared
    /// when any head lands. While set, every turn evaluates "claimed, no head"
    /// ahead of the cadence's triggers, so the one trigger the refused writer
    /// can fire — its own next turn — writes the head. Never set on a board
    /// with a head: `write_head_if_due` reads `last_head` first.
    first_head_owed: bool,
    /// Row 38's memo: the last refusal said, its commit and its cause.
    ///
    /// It keeps the module doc's account of what a refusal does: the op the
    /// head's commit ran, as the wire names it, and the cause rendered as the
    /// line renders it, `{code}: {detail}` ([`render_cause`]) or a malformed
    /// run's own words, so a refusal at the same commit rendering the same is
    /// not said again while it stands; `None` before any refusal and again
    /// once a head lands. Under this lock because the refusal is met inside
    /// the head's own commit, outside the decision's lock span, and the
    /// clearing is taken under it.
    last_refusal: Option<(&'static str, String)>,
    /// The refusals since a head last landed ([`Refusals`]).
    ///
    /// They are what the clearing line names: begun at the first refusal
    /// after a landing, counting every refused attempt after it, said again
    /// or not, and cleared with the line when a head lands. `None` while no
    /// refusal stands.
    refusals: Option<Refusals>,
}

/// The refusals since a head last landed, as the clearing line names them.
struct Refusals {
    /// The position the first refused head would have named.
    since: u64,
    /// The moment the first refusal was met.
    began: Instant,
    /// Every refused attempt, counted whether the memo said it or not.
    attempts: u64,
}

/// A committed pair: a position and the commit chain's value at it.
///
/// Together they name one committed state (wire.md's `(position, chain)`
/// pair): what `/health` serves live, what `/chain?at` recomputes, what a head
/// names, and what its `prev` names of the head before it. The corpus spends
/// "coordinate" on the position alone (wire.md §Reading history, "positions:
/// durable coordinates"; M2's version coordinate, which the kernel pairs with
/// its chain), so the two together take the corpus's own noun: a pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommittedPair {
    position: u64,
    chain: [u8; 32],
}

/// A checkpoint as a head's `base` names it.
///
/// It is its seq and the two hashes its header carries. Named because the two
/// are the same width and mean different things — carried as a tuple, a
/// transposed pair compiles and publishes a head whose `base.chain` is the
/// body hash, permanently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckpointBase {
    seq: u64,
    chain: [u8; 32],
    body_hash: [u8; 32],
}

/// One `skep-head` record (PUB-6.65; wire.md §The other endpoints).
///
/// It is the published head's schema on one card, rendered in the schema's
/// order and read back by the same card, so the writer and the resume cannot
/// spell a member two ways. `type` and `format` are constants of the schema
/// and not fields: every record this build writes carries this build's stamp,
/// and [`HeadRecord::parse`] refuses one that does not.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HeadRecord {
    /// The committed pair the head names.
    ///
    /// It is read off one snapshot before the head's own write opens, so
    /// strictly below its own commit.
    position: u64,
    chain: [u8; 32],
    /// The newest retained checkpoint at or below `position`, or `None`.
    base: Option<CheckpointBase>,
    /// The previous head's committed pair, or `None` at the first.
    prev: Option<CommittedPair>,
}

impl HeadRecord {
    /// Returns the committed pair this head names.
    ///
    /// It is what the next head's `prev` carries.
    fn pair(&self) -> CommittedPair {
        CommittedPair { position: self.position, chain: self.chain }
    }

    /// Returns the record's bytes, hand-marshaled in schema order.
    ///
    /// The order is `type`, `format`, `position`, `chain`, `base`, `prev`,
    /// with no whitespace — not the codec's sorted-key marshal, which would
    /// reorder them. `base` and `prev` are their objects or `null`; no `sig`,
    /// no timestamp (two heads of one board at one position are
    /// byte-identical). Each JSON object is one literal, so the schema's order
    /// is read off the literal itself.
    fn to_bytes(&self) -> Vec<u8> {
        let base = match &self.base {
            Some(CheckpointBase { seq, chain, body_hash }) => format!(
                r#"{{"seq":{seq},"chain":"{}","body_hash":"{}"}}"#,
                hex_string(chain),
                hex_string(body_hash),
            ),
            None => String::from("null"),
        };
        let prev = match &self.prev {
            Some(CommittedPair { position, chain }) => {
                format!(r#"{{"position":{position},"chain":"{}"}}"#, hex_string(chain))
            }
            None => String::from("null"),
        };
        format!(
            r#"{{"type":"{RECORD_TYPE}","format":"{FORMAT_STAMP}","position":{},"chain":"{}","base":{base},"prev":{prev}}}"#,
            self.position,
            hex_string(&self.chain),
        )
        .into_bytes()
    }

    /// Reads back whole a record this build wrote.
    ///
    /// It answers `None` for bytes that are not JSON or that carry another
    /// `type`, another `format`, or a member missing or malformed, which
    /// includes a hash spelled other than as [`hex_string`] writes it; a
    /// member it does not read goes unchecked. The inverse of
    /// [`HeadRecord::to_bytes`].
    fn parse(bytes: &[u8]) -> Option<HeadRecord> {
        let v: Value = serde_json::from_slice(bytes).ok()?;
        if v.get("type")?.as_str()? != RECORD_TYPE || v.get("format")?.as_str()? != FORMAT_STAMP {
            return None;
        }
        let pair = |v: &Value| -> Option<CommittedPair> {
            Some(CommittedPair {
                position: v.get("position")?.as_u64()?,
                chain: parse_lower_hex(v.get("chain")?.as_str()?)?,
            })
        };
        let CommittedPair { position, chain } = pair(&v)?;
        let base = match v.get("base")? {
            Value::Null => None,
            base => Some(CheckpointBase {
                seq: base.get("seq")?.as_u64()?,
                chain: parse_lower_hex(base.get("chain")?.as_str()?)?,
                body_hash: parse_lower_hex(base.get("body_hash")?.as_str()?)?,
            }),
        };
        let prev = match v.get("prev")? {
            Value::Null => None,
            prev => Some(pair(prev)?),
        };
        Some(HeadRecord { position, chain, base, prev })
    }
}

/// Who says a refused commit of the system principal's, and how.
///
/// It is handed to [`HeadWriter::run_commit`] and the three helpers over it
/// with the op refused, as the wire names it, and the cause as the wire
/// renders a rejection ([`render_cause`]): the head writer's own is row 38's
/// memo, [`HeadWriter::say_the_refusal_once`] with the position the head
/// would have named; the registry seed's is its own line, naming the type
/// whose commit the refusal met.
pub(super) type Refused<'a> = &'a dyn Fn(&'static str, String);

/// A head that is due: the decision the turn reaches under the state lock.
///
/// [`HeadWriter::take_turn`] reaches it under the state lock and then acts on
/// it without the lock: the record to publish (the state's `last_head` once
/// it lands) and the clock reading that becomes its `last_head_millis`.
struct DueHead {
    record: HeadRecord,
    now_millis: u64,
}

/// The head writer, owned by [`Commits`].
///
/// It holds its own handle on the engine's one kernel (an [`EngineStores`]
/// clone — the same `Arc<Kernel>`), the mutable state, and the clock.
pub(super) struct HeadWriter {
    stores: EngineStores,
    state: Mutex<HeadState>,
    clock: Clock,
    /// The classed door with the daemon's record ([`Lines`]).
    ///
    /// It is a clone handed at [`HeadWriter::open`] as `commits.log` holds
    /// one: row 38's line, its clearing, the malformed run's and row 40's go
    /// through it.
    lines: Lines,
    /// The test seam behind `skepd::Daemon::refuse_the_next_head_once`.
    ///
    /// With its `_as` sibling, `Some(detail)` arms one driver refusal inside
    /// the driver — the first store call of the next head's write answers a
    /// `durability` rejection carrying `detail` in place of running
    /// ([`HeadWriter::injected_refusal`]) — so the refusal takes row 38's
    /// whole path, exactly as `run_commit` answers a real one: the head
    /// skipped, the last head and the counters as they were, the line said
    /// once per cause. The seam disarms at the one refusal it injects. A
    /// production build, which has no `test-hooks`, has no such field.
    #[cfg(any(test, feature = "test-hooks"))]
    refuse_next_head: Mutex<Option<String>>,
}

impl HeadWriter {
    /// Opens the writer over `stores`, resuming by reading `H` and the feed.
    ///
    /// It reads `H`'s latest member (PUB-6.65, I7 (a)): the record it holds
    /// becomes `last_head` whole, so a head written after a restart carries
    /// the right `prev`, does not re-name a position already published, and is
    /// due by trigger (b) only for a checkpoint the last head did not name; and
    /// the staging draft is found where an earlier uptime minted it. All off
    /// one snapshot. And it reads the feed (the module doc's resume from the
    /// feed): the entries above that position resume trigger (a)'s count and
    /// trigger (c)'s origin — a lost sidecar's bare entries counting, and its
    /// missing times leaving the origin at open.
    ///
    /// **While the walk's region is pending** (`operations.md` §3.3 step 2:
    /// "the head writer's resume counts commits off the kernel's seq while
    /// entries are pending, an over-count, early and never late, the
    /// direction its card accepts"): the feed lacks the region's entries,
    /// so trigger (a)'s count is resumed as `current_seq − last_head.position`
    /// instead — every journal record above the head counted, the region's
    /// system commits and the records within a commit among them, so the
    /// count is at or above the commits that landed and the next head
    /// comes no later than the feed's exact count would bring it; the
    /// hour's origin is read off what the feed holds, or open-time, pending
    /// or not. The direction the `commits_since_head` card accepts: a head
    /// early by at most the over-count, never a duplicate (the position
    /// gate) and never a changed content (D1).
    ///
    /// `lines` is the write path's classed door, cloned in — the one record
    /// the daemon shares — for the three lines this writer says.
    pub(super) fn open(stores: EngineStores, feed: &Feed, lines: &Lines) -> HeadWriter {
        let clock = Clock::new();
        let now = clock.now_millis();
        let snap = stores.kernel().snapshot();
        let last_head = read_latest_head(snap.world());
        let staging_draft = find_staging_draft(snap.world());
        // The feed is the daemon's testimony about its own commits: every
        // entry above the position the last head named landed since that
        // head, the head's own commits among them, testifying
        // `SYSTEM_TESTIMONY`. No head yet, and every retained entry is
        // "since the last head".
        let last_head_position = last_head.as_ref().map_or(0, |h| h.position);
        let resumed = resume_cadence(&feed.entries_above(last_head_position));
        let commits_since_head = match feed.pending_region() {
            Some(_) => snap.seq().0.saturating_sub(last_head_position),
            None => resumed.commits_since_head,
        };
        HeadWriter {
            stores,
            state: Mutex::new(HeadState {
                last_head,
                last_seen_position: snap.seq().0,
                commits_since_head,
                last_head_millis: resumed.last_head_millis.unwrap_or(now),
                staging_draft,
                first_head_owed: false,
                last_refusal: None,
                refusals: None,
            }),
            clock,
            lines: lines.clone(),
            #[cfg(any(test, feature = "test-hooks"))]
            refuse_next_head: Mutex::new(None),
        }
    }

    /// The test seam behind `skepd::Daemon::set_head_writer_clock_millis`.
    ///
    /// It fixes the writer's clock at `millis`, so a test drives trigger (c)
    /// without a `sleep` — the time writer's hour with it, which reads this
    /// clock. Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn set_clock_millis(&self, millis: u64) {
        self.clock.set_millis(millis);
    }

    /// Returns the writer's clock reading: the wall clock, or the seam's.
    ///
    /// It is the reading trigger (c) measures its hour by, offered to the
    /// time writer (`time.rs`) so its hour is measured on the same clock and
    /// driven by the same seam. Read outside every lock.
    pub(super) fn now_millis(&self) -> u64 {
        self.clock.now_millis()
    }

    /// The test seam behind `skepd::Daemon::refuse_the_next_head_once`.
    ///
    /// With its `_as` sibling, it arms one injected driver refusal of the next
    /// due head, its `detail` the given one or [`SEAM_REFUSAL_DETAIL`] under
    /// `None`. Arming again replaces the arm. Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn refuse_next_head_once(&self, detail: Option<&str>) {
        *self.refuse_next_head.lock() = Some(detail.unwrap_or(SEAM_REFUSAL_DETAIL).to_string());
    }

    /// Takes the armed seam's refusal for this commit, disarming the seam.
    ///
    /// The refusal is the rejection the driver would have answered: M10's
    /// `durability` under the commit's own op kind, the armed detail as its
    /// `detail`, so it rides row 38's whole path. Always `None` in
    /// production, where the field does not exist.
    fn injected_refusal(&self, kind: OpKind) -> Option<Rejection> {
        #[cfg(any(test, feature = "test-hooks"))]
        {
            let detail = self.refuse_next_head.lock().take()?;
            let mut refusal = Rejection::classified(kind, RejectCode::Durability, None);
            refusal.detail = Some(detail);
            Some(refusal)
        }
        #[cfg(not(any(test, feature = "test-hooks")))]
        {
            let _ = kind;
            None
        }
    }

    /// Takes the head writer's turn, under the caller's serialization guard.
    ///
    /// It is taken from [`Commits::commit_under`] after every write that door
    /// runs — a refusal and a replay included — and from
    /// [`Commits::take_turn_after_refusal`] after a write refused ahead of the
    /// store: if a commit landed (the kernel's seq, not the answer, is the
    /// arbiter) count it, and if a head is due, write it. The head's own
    /// commits go through [`Commits::commit_recorded`], which gives the head
    /// writer no turn, so they never reach here: neither counted nor able to
    /// re-trigger, by construction. The seq refresh at the end is what keeps
    /// them from reading as a later write's landing: without it, the first
    /// write after a head that lands nothing — a refusal, a replay — would
    /// find the seq past the writer's last look, count the head's own commits
    /// as its own, and could write a head naming the last head's own publish.
    /// A landed commit counts once either way.
    pub(super) fn take_turn(&self, wp: &Commits, serial: &SerialGuard<'_>) {
        self.write_head_if_due(wp, serial, false);
    }

    /// Writes the claim's head `H.1` (signed ops), whatever the cadence says.
    ///
    /// It is the board's first head, naming the committed pair as it stands.
    /// Two callers, one rule. The claim's own step calls it under the guard
    /// the claim committed under ([`Commits::write_first_head`] from the
    /// daemon's claim-flip tail), so `H.1` names the claim's own position and
    /// no write of any kind is admitted between the two; and the daemon's open
    /// calls it on a claimed board whose journal holds no head — the crash
    /// window between the claim's transaction and this one, or a first head
    /// the driver refused while serving — closed before anything is served. A
    /// refusal takes the module doc's account of what a refusal does:
    /// surfaced, the claim standing, and the head owed at the write path's
    /// next turn (the claim's head, owed) or the next open. A no-op on a board
    /// that has a head: the cadence may have written one before or at the
    /// claim (an hour idle before the ceremony's last step is enough), and
    /// then `H.1` stands and this writes nothing — the claim writes one head,
    /// never a second, and a clean reopen of a headed board writes none. The
    /// cadence's counters move by what landed, as in the head writer's turn,
    /// and every head after this one is the cadence's alone. Answers whether a
    /// head landed.
    pub(super) fn write_first_head(&self, wp: &Commits, serial: &SerialGuard<'_>) -> bool {
        self.write_head_if_due(wp, serial, true)
    }

    /// Decides under the state lock whether a head is due, and writes it.
    ///
    /// It is the one body [`HeadWriter::take_turn`] and
    /// [`HeadWriter::write_first_head`] share: due by the cadence's three
    /// triggers, or, with `first`, the board's first head owed. The two differ
    /// in what makes a head due, and in nothing else — except that a first
    /// head the driver refused stays owed (the claim's head, owed), so every
    /// later turn evaluates as a `first` call until a head lands. `true` iff a
    /// head landed.
    fn write_head_if_due(&self, wp: &Commits, serial: &SerialGuard<'_>, first: bool) -> bool {
        // Decide under the state lock, releasing it before any commit.
        let due_head = {
            let mut state = self.state.lock();

            // The claim's head, owed: a refused first head is asked for
            // again at every turn, ahead of the triggers below.
            let first = first || state.first_head_owed;

            // The board's first head is owed once: a board that has one — read
            // off `H` at open, or written this uptime by the claim or by the
            // cadence — is not asked for another, and owes none.
            if state.last_head.is_some() {
                state.first_head_owed = false;
                if first {
                    return false;
                }
            }

            // The pair the head will name — the kernel's committed
            // (seq, chain) off one snapshot, before the head's own write opens.
            let snap = self.stores.kernel().snapshot();
            let position = snap.seq().0;

            // Landed, not merely answered. `commit_under` gives this turn after
            // every write it runs, and a write can answer without committing
            // anything this call: a refusal, an idempotency replay answered
            // from M10's memo, `emit`'s incumbent ack. The kernel's seq is
            // the arbiter — unmoved past the last look, nothing landed:
            // nothing to count, no trigger to evaluate (never while the
            // position has not moved). Writing the first head evaluates
            // regardless — the head writer's turn after the claim's commit
            // already counted the claim, and the open's look is the seq at
            // open — counting nothing it did not see land.
            if position > state.last_seen_position {
                state.last_seen_position = position;
                state.commits_since_head = state.commits_since_head.saturating_add(1);
            } else if !first {
                return false;
            }

            let chain = snap.chain();
            // `base`: the newest retained checkpoint at or below the named
            // position, else null — the kernel's checkpoint header, field by
            // field.
            let base = self
                .stores
                .kernel()
                .newest_checkpoint()
                .filter(|newest| newest.seq.0 <= position)
                .map(|newest| CheckpointBase {
                    seq: newest.seq.0,
                    chain: newest.chain_head,
                    body_hash: newest.body_hash,
                });
            let now = self.clock.now_millis();

            // Never twice for one position: a head sets `last_head` to the
            // record it published, and a landed commit is always above its
            // position — the literal guard, kept beside the seq gate above.
            let last = state.last_head.as_ref();
            let moved = last.map_or(position > 0, |h| position > h.position);
            if !moved {
                return false;
            }
            // Trigger (b): there is a checkpoint for this head's `base` to
            // name, and it is not the one the last head's `base` named.
            let last_base_seq = last.and_then(|h| h.base).map(|b| b.seq);
            let due = first
                || state.commits_since_head >= COUNT_BOUND
                || base.is_some_and(|b| Some(b.seq) != last_base_seq)
                || now.saturating_sub(state.last_head_millis) >= TIME_BOUND_MILLIS;
            if !due {
                return false;
            }
            // `prev`: the previous head's committed pair, null at the first.
            let record = HeadRecord { position, chain, base, prev: last.map(HeadRecord::pair) };
            (DueHead { record, now_millis: now }, first)
        };
        let (due_head, first) = due_head;

        let landed = self.write_head(wp, serial, &due_head.record);
        let mut state = self.state.lock();
        if landed {
            // The clearing (row 38's second line): a head landed, so every
            // refusal since the last one is history — said once, naming this
            // head's position, the attempts refused, the first refused
            // position and how long the refusals lasted, and the memo
            // cleared so the next refusal is news again.
            if let Some(refusals) = state.refusals.take() {
                state.last_refusal = None;
                let cleared = RefusalsClearedLine {
                    landed: due_head.record.position,
                    attempts: refusals.attempts,
                    since: refusals.since,
                    elapsed_ms: refusals.began.elapsed().as_millis(),
                };
                self.lines.say(Class::Landing, cleared);
            }
            state.last_head = Some(due_head.record);
            state.commits_since_head = 0;
            state.last_head_millis = due_head.now_millis;
            state.first_head_owed = false;
        } else if first {
            // A refused first head is owed at the next turn (the claim's
            // head, owed); a refused cadence head is retried by its trigger,
            // which stays due.
            state.first_head_owed = true;
        }
        // The head's own commits — a whole head's, or a refused one's partial
        // (the draft mint, the orphaned insert) — moved the seq: the next
        // evaluation measures "landed" from here, so they count nothing.
        state.last_seen_position = self.stores.kernel().snapshot().seq().0;
        landed
    }

    /// Writes one head: the record atom into the staging draft, then the shot.
    ///
    /// Its two commits are the insert and the publish shot minting the next
    /// member of `H`, the staging draft's mint ahead of them where none is
    /// held ([`HeadWriter::ensure_draft`]). `true` iff both committed — a
    /// failed publish leaves the atom an orphan in the draft (the resume
    /// case), the last head and the counters stay as they were, and the next
    /// commit retries.
    fn write_head(&self, wp: &Commits, serial: &SerialGuard<'_>, record: &HeadRecord) -> bool {
        // The position the head names — what row 38's line names where any
        // of its commits is refused.
        let position = record.position;
        let refused = |act: &'static str, cause: String| self.say_the_refusal_once(position, act, cause);
        let Some(draft) = self.ensure_draft(wp, serial, &refused) else {
            return false;
        };
        let bytes = record.to_bytes();

        // The next free content position of the draft, and the atom there.
        let next_ordinal = {
            let snap = self.stores.kernel().snapshot();
            snap.world().m5().content_count(&draft) + Nat::from(1u32)
        };
        let Some(atom_start) =
            self.commit_insert(wp, serial, &draft, next_ordinal, vec![Val::new(bytes)], &refused)
        else {
            return false;
        };

        // The shot: base is H's current trunk head (or H itself while
        // memberless), extent = that member's full content count so nothing is
        // carried — each member holds exactly its own record (0 at the first
        // head, written while `H` is memberless: PUB-6.65's "extent 0").
        // runs = the new atom alone.
        let h = head_document();
        let (base_member, extent) = {
            let snap = self.stores.kernel().snapshot();
            let world = snap.world();
            let member = trunk_head(world.m3(), &h).unwrap_or_else(|| h.clone());
            let extent = world.m5().content_count(&member);
            (member, extent)
        };
        let run = match Run::new(atom_start, Nat::from(1u32)) {
            Ok(run) => run,
            Err(e) => {
                // Unreachable — the insert answered a content element start —
                // but a silent arm is what I11 (c) forbids, so it is named:
                // the error's own words (`RunError`'s `Display`, never its
                // `Debug`), as row 38 names a refusal — the head's position,
                // the publish it could not build, once per cause, and cleared
                // by the head that next lands.
                let cause = format!("its atom's run is malformed: {e}");
                self.say_the_refusal_once(position, op_name(OpKind::Publish), cause);
                return false;
            }
        };
        let shot = Shot {
            base: Some(Base { member: base_member, extent }),
            draft: Some(draft.clone()),
            runs: vec![ShotRun { origin: draft, run }],
        };
        self.commit_publish(wp, serial, h, shot, &refused).is_some()
    }

    /// Takes the system principal's own commits off the cadence's count.
    ///
    /// It is the look the writer takes after its own head's commits (the
    /// seq refresh [`HeadWriter::write_head_if_due`] ends with), offered to
    /// the registry seed for the same reason: the seed's commits at the open
    /// are the system principal's, not a session's, and the next write's turn
    /// would otherwise find the seq past the writer's last look and count
    /// them as that write's landing — one early count, which this refresh
    /// spares. Under the state lock, held for the one store.
    pub(super) fn mark_own_commits_seen(&self) {
        self.state.lock().last_seen_position = self.stores.kernel().snapshot().seq().0;
    }

    /// Returns the staging draft, minting it now where none is held.
    ///
    /// It is the one found at open or minted by an earlier head this uptime,
    /// else minted now under the system account (a private document,
    /// `published: false`) — once for the life of the board where the mint
    /// lands at [`staging_draft_address`], since every later open finds it
    /// there ([`find_staging_draft`]). The registry seed and the time writer
    /// take it too, so whichever of the three writes first mints it, and the
    /// others find it held. A refusal of the mint is `refused`'s to say.
    pub(super) fn ensure_draft(
        &self,
        wp: &Commits,
        serial: &SerialGuard<'_>,
        refused: Refused<'_>,
    ) -> Option<Address> {
        // Read in a statement of its own, so the state guard drops at the `;`:
        // an `if let` keeps its scrutinee's temporaries alive through its
        // body, and this lock is never to be held across a commit.
        let found = self.state.lock().staging_draft.clone();
        if found.is_some() {
            return found;
        }
        let account = system_account();
        let op = Op::CreateNewDocument { account: account.clone(), published: Some(false) };
        let meta = write_meta(&op)?.attributed(SYSTEM_TESTIMONY.to_string(), None);
        // The refusal lowered as the front door lowers the same error for a
        // `create_new_document` (`lower_txn`, M10's one table).
        let draft = self.run_commit(wp, serial, meta, refused, move || {
            self.stores
                .namespace()
                .create_new_document(SYSTEM_PRINCIPAL, &account, Some(false))
                .map_err(|e| lower_txn(OpKind::CreateNewDocument, e))
        })?;
        if draft != staging_draft_address() {
            // The system principal mints the draft ahead of its one other
            // document (the time document, which the time writer mints after
            // this draft stands), so the first mint under its account is doc
            // 3 by the seed's frontier; anything else means some other
            // writer minted under the system account — surfaced, and the
            // head goes on with the draft it did mint, which the line says
            // (`operations.md` §1.1 row 40).
            self.lines.say(
                Class::Failure,
                DraftMintedElsewhere { minted: &draft, expected: &staging_draft_address() },
            );
        }
        self.state.lock().staging_draft = Some(draft.clone());
        Some(draft)
    }

    /// Commits one `insert` of `values` into `draft` at `ordinal`, as the
    /// system principal, through [`HeadWriter::run_commit`].
    ///
    /// The head's record is one atom; the registry seed's sections are
    /// per-byte values, as prose is. Answers the first minted I-address, the
    /// values I-adjacent from it, or `None` where the driver refused, which
    /// `refused` has said.
    pub(super) fn commit_insert(
        &self,
        wp: &Commits,
        serial: &SerialGuard<'_>,
        draft: &Address,
        ordinal: Nat,
        values: Vec<Val>,
        refused: Refused<'_>,
    ) -> Option<Address> {
        let op = Op::Insert {
            doc: draft.clone(),
            at: VPos::content(ordinal),
            values,
            deposit: Deposit::Undeclared,
        };
        let meta = write_meta(&op)?.attributed(SYSTEM_TESTIMONY.to_string(), None);
        let Op::Insert { doc, at, values, deposit } = op else {
            return None;
        };
        // The refusal lowered as the front door lowers an `insert`'s.
        self.run_commit(wp, serial, meta, refused, move || {
            self.stores
                .vstream()
                .insert(Caller::Principal(SYSTEM_PRINCIPAL), &doc, at, values, deposit)
                .map_err(|e| lower_txn(OpKind::Insert, e))
        })
    }

    /// Commits one publish `shot` into `doc`'s chain, as the system
    /// principal, through [`HeadWriter::run_commit`].
    ///
    /// `doc` is `H` for a head, the registry document for the seed, `T` for
    /// the time writer. The shot is THE PUBLICATION (the link-sets design
    /// §5.7), as the front door commits a session's: M7's composite stages
    /// M5's shot and, for the run it re-inserts from the staging draft, one
    /// correspondence record homed in the draft, in the one commit — three
    /// records beside the shot's own, accruing in the draft at every head,
    /// time record and seed; each producer's run is the atom or the sections
    /// it just inserted, fresh identity no record names, so the twin fence
    /// never fires for it. Answers the member minted, or `None` where the
    /// driver refused, which `refused` has said.
    pub(super) fn commit_publish(
        &self,
        wp: &Commits,
        serial: &SerialGuard<'_>,
        doc: Address,
        shot: Shot,
        refused: Refused<'_>,
    ) -> Option<Address> {
        let op = Op::Publish { doc, shot };
        let meta = write_meta(&op)?.attributed(SYSTEM_TESTIMONY.to_string(), None);
        let Op::Publish { doc, shot } = op else {
            return None;
        };
        // The source consult at the system principal's class, never System's
        // (PUB-6.65): the system account owns H and the draft, so no origin is
        // withheld, and the draft is the system principal's own, so the
        // shot's draft slot passes. The refusal lowered as the front door
        // lowers a `publish`'s.
        let visibility = World::visible_to(Caller::Principal(SYSTEM_PRINCIPAL));
        self.run_commit(wp, serial, meta, refused, move || {
            self.stores
                .linkstore(&visibility)
                .publication(Caller::Principal(SYSTEM_PRINCIPAL), &doc, &shot)
                .map_err(|e| lower_txn(OpKind::Publish, e))
        })
    }

    /// Runs one commit of the system principal's through the head writer's
    /// door.
    ///
    /// The door is [`Commits::commit_recorded`] — recorded and announced like
    /// any write, giving the head writer no turn — and the commit runs as the
    /// system principal: run the driver inside the closure, hand the door the
    /// `AckAddr` its `record`/announce want, and read the committed address
    /// back off the answer the door returns, the one copy of it there is. No
    /// caller reads the committed `Seq`, so the address alone is returned. A
    /// driver refusal is a [`Rejection`] — the store's error lowered through
    /// M10's one table under the op's own kind, so it reads as the wire's
    /// refusal of the same op would — met inside the closure, where it is in
    /// hand, handed to `refused` with the op refused and the cause as the
    /// wire renders it — the head's row 38 memo, said once per commit and
    /// cause with the position the head would have named
    /// ([`HeadWriter::say_the_refusal_once`]), or the registry seed's own
    /// line — and answered with a non-committing `Response` (recorded
    /// nowhere), so the head or the seed's row is skipped and the triggering
    /// write is untouched. The test seam's refusal is taken here too, ahead
    /// of the driver, so it rides the same path.
    pub(super) fn run_commit(
        &self,
        wp: &Commits,
        serial: &SerialGuard<'_>,
        meta: WriteMeta,
        refused: Refused<'_>,
        run: impl FnOnce() -> Result<(Address, Seq), Rejection>,
    ) -> Option<Address> {
        let kind = meta.kind;
        let resp = wp.commit_recorded(serial, meta, || {
            let outcome = match self.injected_refusal(kind) {
                Some(refusal) => Err(refusal),
                None => run(),
            };
            match outcome {
                Ok((addr, at)) => Response::AckAddr { addr, at },
                Err(refusal) => {
                    refused(op_name(kind), render_cause(&refusal));
                    // A no-op answer `record` returns None for: nothing
                    // recorded, nothing announced. Dropped below, never on
                    // the wire.
                    Response::Bool { val: false, as_of: Seq(0) }
                }
            }
        });
        let Response::AckAddr { addr, .. } = resp else {
            return None;
        };
        Some(addr)
    }

    /// Says row 38's line, once per commit and cause.
    ///
    /// This is the line the module doc's account of a refusal names.
    /// `act` is the op of the head's commit the refusal was met at — the
    /// staging draft's mint, the record's insert or the shot's publish, as
    /// the wire names it — and `cause` the refusal as the wire renders a
    /// rejection, `{code}: {detail}` ([`render_cause`]), or, where the shot's
    /// run would not build, that error's own words. Compared under the state
    /// lock with the last one said: the same commit and cause is not said
    /// again; another is said with `position`, the one the head would have
    /// named, and remembered. Every attempt is counted, said or not, and the
    /// first refused position since a landing kept with the moment, for the
    /// clearing line. Said under the lock, so this line and the clearing a
    /// landing says are one order on the stream. Where no head stands yet
    /// the line says what that costs a claimed board ([`HeadRefusedLine`]).
    fn say_the_refusal_once(&self, position: u64, act: &'static str, cause: String) {
        let mut state = self.state.lock();
        let refusals = state.refusals.get_or_insert_with(|| Refusals {
            since: position,
            began: Instant::now(),
            attempts: 0,
        });
        refusals.attempts += 1;
        if state.last_refusal.as_ref().is_some_and(|(a, c)| *a == act && *c == cause) {
            return;
        }
        let first = state.last_head.is_none();
        self.lines.say(Class::Failure, HeadRefusedLine { position, act, cause: &cause, first });
        state.last_refusal = Some((act, cause));
    }
}

/// Returns row 38's cause as the wire renders a rejection: `{code}: {detail}`.
///
/// It is `operations.md` §1.1 row 38's: the code as the wire spells it
/// ([`wire_code`]) and the rejection's own `detail` where it carries one,
/// the code alone otherwise; a `durability` refusal whose I/O kind is
/// `StorageFull` says the operator's words, `the volume is full`, ahead of
/// the OS's text, as the checkpoint's failure line says them. Never a
/// `Debug` rendering: the inner errors are the stores', whose `Display` the
/// daemon cannot assume and whose `Debug` names a variant. The registry
/// seed's line renders its cause through this too, so the two spell one way.
pub(super) fn render_cause(refusal: &Rejection) -> String {
    let code = wire_code(refusal);
    let full = refusal.io_kind == Some(io::ErrorKind::StorageFull);
    match (&refusal.detail, full) {
        (Some(detail), true) => format!("{code}: the volume is full ({detail})"),
        (None, true) => format!("{code}: the volume is full"),
        (Some(detail), false) => format!("{code}: {detail}"),
        (None, false) => code,
    }
}

/// Returns the code as the wire spells it — `durability`, never `Durability`.
///
/// It is read off the JSON codec's own rendering of the rejection
/// ([`JsonCodec`]'s `marshal`, whose `code` member is the transport's one
/// vocabulary, pinned against wire.md), so this line and a client's refusal
/// spell one word and no second table of names stands here. The round trip
/// renders one small JSON document per refusal met — every refused attempt,
/// said or not, since the memo compares the rendered cause — which is what
/// one vocabulary costs while the codec's name table is the codec's own.
fn wire_code(refusal: &Rejection) -> String {
    let rendered = JsonCodec.marshal(&Response::Rejected(refusal.clone()));
    serde_json::from_slice::<Value>(&rendered)
        .ok()
        .and_then(|v| v.get("code")?.as_str().map(str::to_string))
        // Unreachable — the codec renders every rejection with its code —
        // and not a variant name even here.
        .unwrap_or_else(|| "refused".to_string())
}

/// Row 38's line: a head the driver refused.
///
/// It is `operations.md` §1.1 row 38's line (§4 row 31), in the operator
/// stream's words: the position the head would have named, the head's
/// commit the refusal met — the staging draft's `create_new_document`, the
/// record's `insert` or the shot's `publish`, the last a refusal that
/// leaves the insert's atom an orphan in the draft — and the cause as
/// [`render_cause`] renders it, or, where the shot's run would not build,
/// that error's own words: `head writer: the head at position {p} was
/// refused at its {op} ({cause}); no head written this cycle`.
///
/// Where no head stands yet, the line adds what that costs: `; no head
/// stands yet, so a claimed board refuses every attested write
/// attestation_invalid:board_unavailable until one lands — tried again at
/// every write's turn` — the board term is `H.1`'s (signed-ops D13), and a
/// first head refused is owed at every turn (the module doc's account of
/// the claim's head, owed). A pure value the unit suite pins by
/// `to_string()`; emitted under `Class::Failure` through
/// [`HeadWriter::say_the_refusal_once`], once per commit and cause.
struct HeadRefusedLine<'a> {
    position: u64,
    /// The op of the head's commit the refusal met, as the wire names it.
    act: &'static str,
    cause: &'a str,
    /// Whether no head stands yet, so the board has no board term.
    first: bool,
}

impl std::fmt::Display for HeadRefusedLine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "head writer: the head at position {} was refused at its {} ({}); no head written \
             this cycle",
            self.position, self.act, self.cause
        )?;
        if self.first {
            f.write_str(
                "; no head stands yet, so a claimed board refuses every attested write \
                 attestation_invalid:board_unavailable until one lands — tried again at every \
                 write's turn",
            )?;
        }
        Ok(())
    }
}

/// Row 38's clearing line: a head landed, the refusals before it cleared.
///
/// In the operator stream's words it names the position the landed head
/// names, then what the refusals cost — the attempts refused since the last
/// head, the ones the memo kept unsaid among them, the first position refused
/// and how long the refusals stood: `head writer: a head landed at position
/// {p}; {n} refused attempts since position {q}, over {d} ms, are cleared`. A
/// pure value, pinned by `to_string()`; emitted under `Class::Landing` by
/// [`HeadWriter::write_head_if_due`] where a head lands with refusals on the
/// memo, once.
struct RefusalsClearedLine {
    landed: u64,
    attempts: u64,
    since: u64,
    /// From the first refusal to this landing, whole milliseconds.
    elapsed_ms: u128,
}

impl std::fmt::Display for RefusalsClearedLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "head writer: a head landed at position {}; {} refused attempts since position {}, \
             over {} ms, are cleared",
            self.landed, self.attempts, self.since, self.elapsed_ms
        )
    }
}

/// Row 40's line (`operations.md` §1.1 row 40): the draft minted elsewhere.
///
/// In the operator stream's words it says the staging draft minted somewhere
/// other than the address the seed's frontier pins, the cause, and what still
/// serves: the head goes on with the draft it minted. A pure value the unit
/// suite pins by `to_string()`; emitted under `Class::Failure`.
struct DraftMintedElsewhere<'a> {
    minted: &'a Address,
    expected: &'a Address,
}

impl std::fmt::Display for DraftMintedElsewhere<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "head writer: the staging draft minted at {}, not at {} — another writer minted \
             under the system account; the head goes on with the draft it minted",
            self.minted, self.expected
        )
    }
}

/// The cadence's two counters as a restart resumes them from the feed.
///
/// They are read off the feed's entries above the last head's position (the
/// module doc's resume from the feed). The count is exact where every entry
/// above the position kept its testimony; a bare entry counts, the head's
/// own among them, so a lost testimony can make it early and never late. While
/// the walk's region is pending the writer takes the kernel's seq in its
/// place ([`HeadWriter::open`]), early and never late, and the origin from
/// here.
struct ResumedCadence {
    /// Entries whose testimony is not `"system"`.
    ///
    /// They are every commit landed since the head that was not the head's
    /// own; a bare entry, its testimony lost, counts.
    commits_since_head: u64,
    /// The head's own time: the last `"system"` entry's recorded `time`.
    ///
    /// That entry is the head's publish, or a later attempt's orphaned
    /// insert or draft mint, either way the board's most recent head work —
    /// else the first entry above the position carrying a time (a witness no
    /// earlier than the head, so the hour fires no sooner than it is owed),
    /// else `None`: open-time.
    last_head_millis: Option<u64>,
}

/// Resumes the cadence from the feed's entries above the last head's position.
///
/// They come in position order, as [`Feed::entries_above`] hands them over.
fn resume_cadence(above: &[(u64, CommitMeta)]) -> ResumedCadence {
    let is_system = |meta: &CommitMeta| {
        matches!(
            meta,
            CommitMeta::Recorded { key: Some(testimony), .. } if testimony == SYSTEM_TESTIMONY
        )
    };
    let commits_since_head = above.iter().filter(|(_, meta)| !is_system(meta)).count() as u64;
    let last_head_millis = above
        .iter()
        .rev()
        .find(|(_, meta)| is_system(meta))
        .and_then(|(_, meta)| meta.time())
        .or_else(|| above.iter().find_map(|(_, meta)| meta.time()));
    ResumedCadence { commits_since_head, last_head_millis }
}

/// Returns `H`'s latest member's recorded head: the resume by reading.
///
/// It is `None` when `H`'s trunk chain has no member yet (or its record is
/// not a head this build wrote — [`HeadRecord::parse`] — treated as no head,
/// so the next trigger writes a fresh one). The record is the atom at content
/// position 1 of the trunk head, read off M5's point resolution and M4's
/// value.
fn read_latest_head(world: &World) -> Option<HeadRecord> {
    let h = head_document();
    let member = trunk_head(world.m3(), &h)?;
    read_head_member(world, &member)
}

/// Returns the head record one member of `H` holds.
///
/// It is the member's atom at content position 1, parsed as this build
/// writes it.
fn read_head_member(world: &World, member: &Address) -> Option<HeadRecord> {
    let i_addr = world.m5().point(member, &VPos::content(Nat::from(1u32)))?;
    HeadRecord::parse(world.content().value_at(i_addr.tumbler())?.as_bytes())
}

/// Returns the board term of the entry frame (signed-ops D13): `H.1`'s pair.
///
/// It is the committed `(position, chain)` pair of `H.1`, `1.1.0.1.0.2.1` —
/// `H`'s birth version ([`birth_version`]), the member the first head's shot
/// mints, pinned forever (wire.md §The other endpoints: "`H.k`, the k-th
/// version member, is pinned forever") — durable (it survives reclamation as
/// checkpoint state), guest-readable (`retrieve_v` on the bare member),
/// board-unique — read off the snapshot the write's gates stand on. On a
/// claimed board it is present from the claim on where the head writer's
/// driver admits `H.1`: the claim's own step writes it
/// ([`HeadWriter::write_first_head`]) and the daemon's open writes it where a
/// crash split the two. `None` on a claimed board therefore names one of two
/// states, and the check's `board_unavailable` is the refusal of both: a
/// first head the driver refused — a refusal the claim survives (on a healthy
/// kernel, M2's `TxnError::Durability`: ENOSPC, the OS refusing entropy),
/// surfaced on the operator stream (I11 (c)), and written at the write path's
/// next turn, where it is owed, or the next open (the module doc: the first
/// head is the claim's) — or a journal damaged below `H.1` (the member gone,
/// or its record not one this build reads). Answered as the corpus's term,
/// [`BoardTerm`], and not as its shape: it is a committed pair, but the one
/// fixed from the claim on, never the live pair `/health` serves.
pub(crate) fn board_term(world: &World) -> Option<BoardTerm> {
    let first_head = birth_version(world.m3(), &head_document())?;
    let rec = read_head_member(world, &first_head)?;
    Some(BoardTerm { log_position: rec.position, chain: rec.chain })
}

/// Returns the staging draft's address: doc 3 of the system account.
///
/// It is `1.1.0.1.0.3`: genesis registers doc 1 and doc 2
/// ([`skep_namespace::M3State::genesis`]), the system principal holds no key
/// and has no session, so the head writer, the registry seed and the time
/// writer — which share this one draft through [`HeadWriter::ensure_draft`]
/// — are the only writers under the account, and the first mint of any of
/// them lands here by the document chain's frontier; the time writer's own
/// document, minted after it, lands at doc 4
/// ([`skep_namespace::time_document`]). Pinned so a reopened writer can find
/// the draft (resume by reading) instead of minting a new private document
/// per uptime.
///
/// # Panics
///
/// Panics if `1.1.0.1.0.3` is not a nonempty, T4-valid address; it is one,
/// so neither `expect` fires.
pub(super) fn staging_draft_address() -> Address {
    let t = Tumbler::new([1u32, 1, 0, 1, 0, 3].into_iter().map(Nat::from))
        .expect("a six-component sequence is nonempty");
    validate(t).expect("the staging draft 1.1.0.1.0.3 is T4-valid by construction")
}

/// Returns the staging draft an earlier uptime minted, if any.
///
/// It is [`staging_draft_address`] when that is a registered, unpublished
/// document — the only shape the head writer ever gives it — else `None`,
/// and the first head mints it.
fn find_staging_draft(world: &World) -> Option<Address> {
    let draft = staging_draft_address();
    let m3 = world.m3();
    (m3.is_registered_document(&draft) && !m3.published(&draft)).then_some(draft)
}

#[cfg(test)]
mod tests;
