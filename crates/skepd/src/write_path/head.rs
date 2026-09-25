//! The PUBLISHED HEAD writer (PUB-6.65, RES-304; QUEUE item 10 piece 2) — the
//! board's own daemon writing the head document `H` = `1.1.0.1.0.2` as a NEW
//! PUBLISHED VERSION per head, in-process as the system account's principal
//! ([`SYSTEM_PRINCIPAL`]) with NO session, on the write path's cadence.
//!
//! WHAT A HEAD IS. One `skep-head` record — `type`, `format`, `position`,
//! `chain`, `base`, `prev`, in THAT schema order, no whitespace, UNSIGNED —
//! whose `(position, chain)` is the kernel's committed pair read off ONE
//! [`Snapshot`](skep_kernel) BEFORE the head's own write opens (the value
//! `/health` serves; read here off the kernel directly, not through febe). A
//! head names a coordinate STRICTLY BELOW its own commit and never its own
//! commit — no bytes can carry their own hash — so consecutive heads are
//! chained through the journal's own chain by construction, `prev` being
//! navigation (PUB-6.65's recursion rule). `/health` is the LIVE pair, `H` the
//! DURABLE record. The schema is [`HeadRecord`]'s, on one card.
//!
//! HOW IT LANDS. Per head, two commits under the SAME serialization lock the
//! triggering write holds, each through the head writer's door
//! ([`WritePath::commit_recorded`]) with testimony [`SYSTEM_TESTIMONY`]: (1)
//! one `insert` of the head record atom into a private STAGING DRAFT (minted
//! ONCE under the system account, `published: false`, and reused — across
//! restarts too: it is [`staging_draft_address`], doc 3 of the system
//! account, the one document the system principal ever mints, and a reopened
//! writer finds it registered rather than minting another; the head reaches
//! `H` and that draft and NO other document), then (2) one `publish` shot
//! minting the next member of `H`'s trunk chain — `base` = `H`'s current
//! trunk head with its extent set to that member's full content count (so
//! NOTHING is carried and each member holds exactly its own record; 0 at the
//! first head, written while `H` is memberless), `draft` = the staging draft,
//! `runs` = the new atom's one run. The shot's source consult runs at
//! `visible_to(Caller::Principal(SYSTEM))`, never System's — the system
//! principal owns `H` and the draft, so it never withholds.
//!
//! THE CADENCE, on the write path with no clock thread — evaluated after
//! every write the write path's session door runs ([`HeadWriter::take_turn`],
//! reached from `commit_under`): a head is due when (a) ≥ [`COUNT_BOUND`]
//! commits that are NOT the writer's own have LANDED since the last head, OR
//! (b) the newest retained checkpoint is not the one the last head attested
//! (its `base`), OR (c) ≥ [`TIME_BOUND_MILLIS`] have elapsed since the last
//! head AND the position moved. Never on a peer's request; never while the
//! position has not moved; never twice for one position (the head's own
//! commits ride the head writer's door, which gives the head writer no turn,
//! so they are neither counted nor able to re-trigger). LANDED, not merely
//! acked: the turn is taken after every write `commit_under` runs — an ack
//! that committed nothing this call (an idempotency replay answered from
//! M10's memo, `emit`'s incumbent ack) and a refusal included; the kernel's
//! seq, not the answer, says whether a commit landed, and one that did not
//! counts nothing and evaluates no trigger. RESUME BY READING: at open the
//! writer reads `H`'s latest member — its `position` and `chain` (the next
//! head's `prev`; a head is owed only once the position moves past it) and
//! its `base` (trigger (b)'s reference: a checkpoint taken after that head,
//! before or after a restart, is attested by the next head) — and finds the
//! staging draft where it left it; a crash between the insert and the shot
//! leaves an orphan atom in the draft and no member, and the next head's shot
//! names the newer atom (PUB-2.26's no-residue).
//!
//! RESUME FROM THE FEED (the chain's open items, item 2). The cadence's two
//! counters are RESUMED at open from the change feed's testimony about the
//! commits landed ABOVE the recorded head's position (`Feed::entries_above`),
//! so that PUB-6.65's "64 commits … have landed since the last head" and "one
//! hour has passed since the last head" are true of the BOARD across a
//! restart and not of the process: `commits_since_head` is the count of those
//! entries whose testimony is not `"system"` — a bare entry counts,
//! conservative by at most the head's own commits, so a head fires at most a
//! few commits early and never twice — and the hour's origin is the recorded
//! `time` of the head's own last entry, the last testifying `"system"` (else
//! the first entry above the position carrying a time; else open-time). The
//! clock is therefore the feed's own: [`wall_clock_millis`], the one reading
//! both take. A LOST sidecar leaves the COUNT early and never late — the
//! reopen walk re-covers every retained position as a bare entry, and every
//! one above the position counts, the head's own among them (their testimony
//! gone), which is the "at most the head's own commits" above — and the HOUR
//! measured from open, the one origin then on record. D1 is kept — a gate
//! reads testimony to decide WHEN, and the head's bytes stay a pure function
//! of the root; AUTH-4.56's rewritable sidecar can move one head's timing
//! within the bounds the triggers already allow, never a duplicate and never
//! a changed content.
//!
//! WHAT A REFUSAL DOES. A driver refusal on any of the head's commits is a
//! SURFACED failure (I11 (c), PUB-5.75: never a board left silently headless):
//! a `skepd:` notice names it, the head is skipped for this cycle with the
//! writer's state unadvanced so the next landed commit retries, and the
//! triggering write is untouched — it committed, and its ack is owed whatever
//! the daemon's own write did. The daemon opens its kernel `Fsync` only, so a
//! head is never written over an in-memory kernel (whose chain is the zero
//! seed at every coordinate); a poisoned kernel refuses the triggering write
//! first, so no head is attempted over it.
//!
//! WHY NOT `Caller::System`. That is M9's rule-fire path (PUB-6.28), which
//! mints nothing and carries three registration conditions the head cannot
//! meet. The head writer acts AS the genesis-seeded system principal on M3/M5,
//! never constructing `Caller::System`; every ω check passes because the system
//! account owns `H` and its draft, and nothing in the engine is widened.

use parking_lot::Mutex;
use serde_json::Value;
use skep_address::{validate, Address, Nat, Tumbler};
use skep_arrangement::{trunk_head, Base, Caller, Deposit, HasM5, Run, Shot, ShotRun, VPos};
use skep_content::{HasContent, Val};
use skep_engine::{EngineStores, World};
use skep_febe::{Op, Response, Stores};
use skep_kernel::Seq;
use skep_namespace::{head_document, system_account, HasM3, SYSTEM_PRINCIPAL};

use super::{write_meta, SerialGuard, WriteMeta, WritePath};
use crate::codec::{hex_string, parse_lower_hex};
use crate::feed::Feed;
use crate::notice;
use crate::sidecar::{wall_clock_millis, CommitMeta};

/// The head record's `format` member — the journal stamp in force (`SKJ4`),
/// which names the hash and the byte format the `chain` value was computed
/// under, so a newer daemon reading an older head knows which chain it belongs
/// to. `SKJ4` since the chain's salt (2026-09-24): every chain value is now
/// SHA-256 over a preimage carrying a per-transaction salt, so a head naming
/// `SKJ3` belongs to a chain no `SKJ4` board recomputes. The stamp is the one
/// member that moved; the head's schema and its other bytes are as they were.
const FORMAT_STAMP: &str = "SKJ4";

/// The head record's `type` member — one spelling for the writer and the
/// resume that reads it back.
const RECORD_TYPE: &str = "skep-head";

/// The published head's TESTIMONY (wire.md §The change feed, `key`'s third
/// value): what the head writer's own commits record in place of a
/// session's — made in-process as the system account's principal with NO
/// session, so no fingerprint and no `"bare"` is true of them. One spelling
/// because the resume READS it back ([`resume_cadence`]) to tell the head's
/// own commits from the ones the cadence counts.
pub(super) const SYSTEM_TESTIMONY: &str = "system";

/// The count bound (PUB-6.65, RES-304): a head is due once this many commits
/// that are not the writer's own have landed since the last head. 64 — at
/// that count the unheld tail a rewrite can hide in is ≤ 64 commits and the
/// heads are ~1/64 of the commits, ~19 bytes per user commit amortized (the
/// investigation's §3.3 table). Evaluated on the write path, never by a
/// thread — the posture the kernel's own checkpoint cadence takes, which
/// `server.rs` configures.
const COUNT_BOUND: u64 = 64;

/// The time bound (PUB-6.65): a head is also due once this long has passed
/// since the last head AND the position has moved, so a slow board's head
/// does not go stale beyond an hour — evaluated LAZILY on the next commit,
/// never by a thread, and never writing a duplicate for a position that has
/// not moved.
const TIME_BOUND_MILLIS: u64 = 3_600_000; // one hour

/// The head writer's own clock, so the time bound (trigger (c)) is drivable in
/// tests through a seam rather than a `sleep`. In production `now_millis` is
/// [`wall_clock_millis`] — the one reading of the clock the feed stamps each
/// commit's `time` with, so the hour the resume takes from the head's own
/// entry (the module doc's RESUME FROM THE FEED) is measured on the clock
/// that recorded it; a wall clock that steps is tolerated by the trigger's
/// `saturating_sub`, and the cost of a step is one head early or late by the
/// step, never a duplicate. [`Clock::set_millis`] overrides it with a fixed
/// reading (the test seam, reached through
/// [`crate::Daemon::set_head_writer_clock_millis`]), which a test therefore
/// sets RELATIVE TO the wall clock rather than at small numbers a resumed
/// origin would dwarf.
///
/// Its lock is innermost: [`HeadWriter::take_turn`] reads it under the state
/// lock, and nothing holding it takes another — the reading is copied out in
/// one statement, so the wall-clock read itself runs under no lock at all.
struct Clock {
    /// A test's fixed reading, held until changed; `None` — the only state
    /// production ever sees — reads [`wall_clock_millis`]. An `Option` and
    /// not a sentinel: every `u64` is a reading a test may fix, `u64::MAX`
    /// (the far-future "the hour has certainly passed") included, and a
    /// sentinel drawn from that domain would read the wall clock for its one
    /// value in silence.
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

    fn set_millis(&self, millis: u64) {
        *self.fixed_millis.lock() = Some(millis);
    }
}

/// The writer's mutable state — everything the trigger reads and the head
/// updates. Behind a [`Mutex`], but never held across a commit: the decision
/// is taken under it and it is dropped before any head write, which takes it
/// again for the staging draft ([`HeadWriter::ensure_draft`]); `parking_lot`'s
/// lock is not re-entrant, so holding it across the write would deadlock the
/// write on itself.
struct HeadState {
    /// The record the most recent head PUBLISHED — read off `H` at open, set
    /// by each head that lands, never reset by a restart; `None` before the
    /// first head ever. Every reference the cadence takes to "the last head"
    /// is a reading of this one value: "the position moved" and "never twice
    /// for one position" read its `position`, the next head's `prev` is its
    /// [`HeadRecord::pair`], and trigger (b)'s reference is its `base`
    /// — the checkpoint the last head ATTESTED — so a checkpoint that landed
    /// after it is attested by the next head, whichever side of a restart
    /// the last one was written on.
    last_head: Option<HeadRecord>,
    /// The kernel's committed seq as of the writer's last look — at open, at
    /// each evaluation, and after the head's own commits — so a write that
    /// LANDED nothing (a refusal, an idempotency replay, an incumbent ack) is
    /// told from a commit: the seq did not pass this.
    last_seen_position: u64,
    /// Commits that are not the writer's own since the last head — trigger
    /// (a)'s count. Resumed at open from the feed's entries above the last
    /// head's position (the module doc's RESUME FROM THE FEED), so a board
    /// restarted every few commits still reaches [`COUNT_BOUND`]; where the
    /// sidecar was lost, every bare entry the reopen walk re-covered above
    /// that position counts, the head's own among them — early by at most
    /// those, never late.
    commits_since_head: u64,
    /// The clock reading at the last head — trigger (c)'s base, in
    /// [`wall_clock_millis`]'s domain. Resumed at open from the last head's own
    /// recorded `time` in the feed (RESUME FROM THE FEED), so after a reopen
    /// the hour is measured from the last head the BOARD wrote and not from
    /// this open; the head itself carries no timestamp (two heads of one board
    /// at one position are byte-identical), so a bare or absent sidecar leaves
    /// this at open-time, the one origin then on record.
    last_head_millis: u64,
    /// The staging draft — [`staging_draft_address`] once it is registered,
    /// found at open or minted at first need; `None` only on a board that has
    /// never written a head.
    staging_draft: Option<Address>,
}

/// A COMMITTED PAIR — a position and the commit chain's value AT it, which
/// together name one committed state (wire.md's `(position, chain)` pair):
/// what `/health` serves live, what `/chain?at` recomputes, what a head
/// names, and what its `prev` names of the head before it. The corpus spends
/// "coordinate" on the POSITION alone (wire.md §Reading history, "positions:
/// durable coordinates"; M2's version coordinate, which the kernel PAIRS with
/// its chain), so the two together take the corpus's own noun: a pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommittedPair {
    position: u64,
    chain: [u8; 32],
}

/// A checkpoint as a head's `base` names it: its seq and the two hashes its
/// header carries. Named because the two are the same width and mean
/// different things — carried as a tuple, a transposed pair compiles and
/// publishes a head whose `base.chain` is the body hash, permanently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckpointBase {
    seq: u64,
    chain: [u8; 32],
    body_hash: [u8; 32],
}

/// One `skep-head` record (PUB-6.65; wire.md §The other endpoints) — the
/// published head's SCHEMA on one card, rendered in the schema's order and
/// read back by the same card, so the writer and the resume cannot spell a
/// member two ways. `type` and `format` are constants of the schema and not
/// fields: every record this build writes carries this build's stamp, and
/// [`HeadRecord::parse`] refuses one that does not.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HeadRecord {
    /// The committed pair the head names — read off ONE snapshot before the
    /// head's own write opens, so strictly below its own commit.
    position: u64,
    chain: [u8; 32],
    /// The newest retained checkpoint at or below `position`, or `None`.
    base: Option<CheckpointBase>,
    /// The previous head's committed pair, or `None` at the first.
    prev: Option<CommittedPair>,
}

impl HeadRecord {
    /// The committed pair this head names — what the NEXT head's `prev`
    /// carries.
    fn pair(&self) -> CommittedPair {
        CommittedPair { position: self.position, chain: self.chain }
    }

    /// The record's bytes, hand-marshaled in SCHEMA order (`type`, `format`,
    /// `position`, `chain`, `base`, `prev`) with no whitespace — NOT the
    /// codec's sorted-key marshal, which would reorder them. `base` and
    /// `prev` are their objects or `null`; no `sig`, no timestamp (two heads
    /// of one board at one position are byte-identical). Each JSON object is
    /// ONE literal, so the schema's order is read off the literal itself.
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

    /// A record THIS BUILD wrote, read back whole — `None` for anything else:
    /// not JSON, another `type`, another `format`, or a member missing or
    /// malformed, which includes a hash spelled other than as [`hex_string`]
    /// writes it. The inverse of [`HeadRecord::to_bytes`].
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

/// A head that is DUE — the decision [`HeadWriter::take_turn`] reaches under
/// the state lock and then acts on without it: the record to publish (the
/// state's `last_head` once it lands) and the clock reading that becomes its
/// `last_head_millis`.
struct DueHead {
    record: HeadRecord,
    now_millis: u64,
}

/// The head writer, owned by [`WritePath`]: its own handle on the engine's one
/// kernel (an [`EngineStores`] clone — the same `Arc<Kernel>`), the mutable
/// state, and the clock.
pub(super) struct HeadWriter {
    stores: EngineStores,
    state: Mutex<HeadState>,
    clock: Clock,
}

impl HeadWriter {
    /// Open the writer over `stores`, RESUMING by reading `H`'s latest member
    /// (PUB-6.65, I7 (a)): the record it holds becomes `last_head` whole, so a
    /// head written after a restart carries the right `prev`, does not re-name
    /// a position already published, and attests a checkpoint the last head
    /// did not name; and the staging draft is found where an earlier uptime
    /// minted it. All off ONE snapshot. And by reading the FEED (the module
    /// doc's RESUME FROM THE FEED): the entries above that position resume
    /// trigger (a)'s count and trigger (c)'s origin — a lost sidecar's bare
    /// entries counting, and its missing times leaving the origin at open.
    pub(super) fn open(stores: EngineStores, feed: &Feed) -> HeadWriter {
        let clock = Clock::new();
        let now = clock.now_millis();
        let snap = stores.kernel().snapshot();
        let last_head = read_recorded_head(snap.world());
        let staging_draft = find_staging_draft(snap.world());
        // The feed is the daemon's testimony about its own commits: every
        // entry above the position the last head named landed since that
        // head, the head's own commits among them, testifying
        // `SYSTEM_TESTIMONY`. No head yet, and every retained entry is
        // "since the last head".
        let resumed =
            resume_cadence(&feed.entries_above(last_head.as_ref().map_or(0, |h| h.position)));
        HeadWriter {
            stores,
            state: Mutex::new(HeadState {
                last_head,
                last_seen_position: snap.seq().0,
                commits_since_head: resumed.commits_since_head,
                last_head_millis: resumed.last_head_millis.unwrap_or(now),
                staging_draft,
            }),
            clock,
        }
    }

    /// The test seam behind [`crate::Daemon::set_head_writer_clock_millis`]:
    /// fix the writer's clock at `millis`, so a test drives trigger (c)
    /// without a `sleep`. Not a stable API.
    pub(super) fn set_clock_millis(&self, millis: u64) {
        self.clock.set_millis(millis);
    }

    /// THE HEAD WRITER'S TURN, taken from [`WritePath::commit_under`] after
    /// every write that door runs — a refusal and a replay included — under
    /// the caller's serialization guard: if a commit LANDED (the kernel's seq,
    /// not the answer, is the arbiter) count it, and if a head is DUE, write
    /// it. The head's own commits go through [`WritePath::commit_recorded`],
    /// which gives the head writer no turn, so they never reach here: neither
    /// counted nor able to re-trigger, by construction. The seq refresh at the
    /// end is what keeps them from reading as a LATER write's landing: without
    /// it, the first write after a head that lands nothing — a refusal, a
    /// replay — would find the seq past the writer's last look, count the
    /// head's own commits as its own, and could write a head naming the last
    /// head's own publish. A landed commit counts once either way.
    pub(super) fn take_turn(&self, wp: &WritePath, serial: &SerialGuard<'_>) {
        // Decide under the state lock, releasing it before any commit.
        let due_head = {
            let mut state = self.state.lock();

            // The pair the head will name — the kernel's committed
            // (seq, chain) off ONE snapshot, before the head's own write opens.
            let snap = self.stores.kernel().snapshot();
            let position = snap.seq().0;

            // LANDED, not merely answered. `commit_under` gives this turn after
            // every write it runs, and a write can answer without committing
            // anything this call: a refusal, an idempotency replay answered
            // from M10's memo, `emit`'s incumbent ack. The kernel's seq is
            // the arbiter — unmoved past the last look, nothing landed:
            // nothing to count, no trigger to evaluate (never while the
            // position has not moved).
            if position <= state.last_seen_position {
                return;
            }
            state.last_seen_position = position;
            state.commits_since_head = state.commits_since_head.saturating_add(1);

            let chain = snap.chain();
            // `base`: the newest retained checkpoint at or below the named
            // position, else null — the kernel's triple named here, in
            // `Kernel::newest_checkpoint`'s documented order, at the one place
            // it is unpacked.
            let base = self
                .stores
                .kernel()
                .newest_checkpoint()
                .filter(|(seq, _, _)| seq.0 <= position)
                .map(|(seq, chain_head, body_hash)| CheckpointBase {
                    seq: seq.0,
                    chain: chain_head,
                    body_hash,
                });
            let now = self.clock.now_millis();

            // Never twice for one position: a head sets `last_head` to the
            // record it published, and a landed commit is always above its
            // position — the literal guard, kept beside the seq gate above.
            let last = state.last_head.as_ref();
            let moved = last.map_or(position > 0, |h| position > h.position);
            if !moved {
                return;
            }
            // Trigger (b): there is a checkpoint for this head to attest, and
            // it is not the one the last head attested.
            let attested = last.and_then(|h| h.base).map(|b| b.seq);
            let due = state.commits_since_head >= COUNT_BOUND
                || base.is_some_and(|b| Some(b.seq) != attested)
                || now.saturating_sub(state.last_head_millis) >= TIME_BOUND_MILLIS;
            if !due {
                return;
            }
            // `prev`: the previous head's committed pair, null at the first.
            let record = HeadRecord { position, chain, base, prev: last.map(HeadRecord::pair) };
            DueHead { record, now_millis: now }
        };

        let landed = self.write_head(wp, serial, &due_head.record);
        let mut state = self.state.lock();
        if landed {
            state.last_head = Some(due_head.record);
            state.commits_since_head = 0;
            state.last_head_millis = due_head.now_millis;
        }
        // The head's own commits — a whole head's, or a refused one's partial
        // (the draft mint, the orphaned insert) — moved the seq: the next
        // evaluation measures "landed" from here, so they count nothing.
        state.last_seen_position = self.stores.kernel().snapshot().seq().0;
    }

    /// The two commits of one head: the record atom into the staging draft,
    /// then the publish shot minting the next member of `H`. `true` iff BOTH
    /// committed — a failed publish leaves the atom an orphan in the draft (the
    /// resume case), the state is not advanced, and the next commit retries.
    fn write_head(&self, wp: &WritePath, serial: &SerialGuard<'_>, record: &HeadRecord) -> bool {
        let Some(draft) = self.ensure_draft(wp, serial) else {
            return false;
        };
        let bytes = record.to_bytes();

        // The next free content position of the draft, and the atom there.
        let next_ordinal = {
            let snap = self.stores.kernel().snapshot();
            snap.world().m5().content_count(&draft) + Nat::from(1u32)
        };
        let Some(atom_start) = self.commit_insert(wp, serial, &draft, next_ordinal, bytes) else {
            return false;
        };

        // The shot: base is H's current trunk head (or H itself while
        // memberless), extent = that member's full content count so NOTHING is
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
                // but a silent arm is what I11 (c) forbids, so it is named.
                notice::line(format_args!(
                    "head writer: the head atom's run is malformed ({e:?}); no head written this cycle"
                ));
                return false;
            }
        };
        let shot = Shot {
            base: Some(Base { member: base_member, extent }),
            draft: Some(draft.clone()),
            runs: vec![ShotRun { origin: draft, run }],
        };
        self.commit_publish(wp, serial, h, shot).is_some()
    }

    /// The staging draft: the one found at open or minted by an earlier head
    /// this uptime, else minted now under the system account (a private
    /// document, `published: false`) — ONCE for the life of the board, since
    /// every later open finds it ([`find_staging_draft`]).
    fn ensure_draft(&self, wp: &WritePath, serial: &SerialGuard<'_>) -> Option<Address> {
        // Read in a statement of its own, so the state guard drops at the `;`:
        // an `if let` keeps its scrutinee's temporaries alive through its
        // body, and this lock is never to be held across a commit.
        let found = self.state.lock().staging_draft.clone();
        if found.is_some() {
            return found;
        }
        let account = system_account();
        let op = Op::CreateNewDocument { account: account.clone(), published: Some(false) };
        let meta = write_meta(&op)?.attributed(SYSTEM_TESTIMONY.to_string());
        let draft = self.run_commit(wp, serial, meta, move || {
            self.stores
                .namespace()
                .create_new_document(SYSTEM_PRINCIPAL, &account, Some(false))
                .map_err(|e| format!("staging draft mint refused: {e:?}"))
        })?;
        if draft != staging_draft_address() {
            // The system principal mints nothing else, so the first mint under
            // its account is doc 3 by the seed's frontier; anything else means
            // some other writer minted under the system account — surfaced,
            // and the head goes on with the draft it did mint.
            notice::line(format_args!(
                "head writer: the staging draft minted at {draft}, not at {} — another writer minted under the system account",
                staging_draft_address()
            ));
        }
        self.state.lock().staging_draft = Some(draft.clone());
        Some(draft)
    }

    fn commit_insert(
        &self,
        wp: &WritePath,
        serial: &SerialGuard<'_>,
        draft: &Address,
        ordinal: Nat,
        bytes: Vec<u8>,
    ) -> Option<Address> {
        let op = Op::Insert {
            doc: draft.clone(),
            at: VPos::content(ordinal),
            values: vec![Val::new(bytes)],
            deposit: Deposit::Undeclared,
        };
        let meta = write_meta(&op)?.attributed(SYSTEM_TESTIMONY.to_string());
        let Op::Insert { doc, at, values, deposit } = op else {
            return None;
        };
        self.run_commit(wp, serial, meta, move || {
            self.stores
                .vstream()
                .insert(Caller::Principal(SYSTEM_PRINCIPAL), &doc, at, values, deposit)
                .map_err(|e| format!("head atom insert refused: {e:?}"))
        })
    }

    fn commit_publish(
        &self,
        wp: &WritePath,
        serial: &SerialGuard<'_>,
        h: Address,
        shot: Shot,
    ) -> Option<Address> {
        let op = Op::Publish { doc: h, shot };
        let meta = write_meta(&op)?.attributed(SYSTEM_TESTIMONY.to_string());
        let Op::Publish { doc, shot } = op else {
            return None;
        };
        // The source consult at the SYSTEM PRINCIPAL's class, never System's
        // (PUB-6.65): the system account owns H and the draft, so no origin is
        // withheld.
        let visibility = World::visible_to(Caller::Principal(SYSTEM_PRINCIPAL));
        self.run_commit(wp, serial, meta, move || {
            self.stores
                .vstream()
                .publish(Caller::Principal(SYSTEM_PRINCIPAL), &doc, shot, &visibility)
                .map_err(|e| format!("head publish refused: {e:?}"))
        })
    }

    /// One head commit through the head writer's door,
    /// [`WritePath::commit_recorded`] — recorded and announced like any
    /// write, giving the head writer no turn — as the system principal: run
    /// the driver inside the closure, hand the door the `AckAddr` its
    /// `record`/announce want, and read the committed address back off the
    /// answer the door returns, the one copy of it there is. No caller reads
    /// the committed `Seq`, so the address alone is returned. A driver
    /// refusal is named inside the closure, where it is in hand, and answered
    /// with a non-committing `Response` (recorded nowhere), so the head is
    /// skipped and the triggering write is untouched.
    fn run_commit(
        &self,
        wp: &WritePath,
        serial: &SerialGuard<'_>,
        meta: WriteMeta,
        run: impl FnOnce() -> Result<(Address, Seq), String>,
    ) -> Option<Address> {
        let resp = wp.commit_recorded(serial, meta, || match run() {
            Ok((addr, at)) => Response::AckAddr { addr, at },
            Err(e) => {
                notice::line(format_args!("head writer: {e}; no head written this cycle"));
                // A no-op answer `record` returns None for: nothing recorded,
                // nothing announced. Dropped below, never on the wire.
                Response::Bool { val: false, as_of: Seq(0) }
            }
        });
        let Response::AckAddr { addr, .. } = resp else {
            return None;
        };
        Some(addr)
    }
}

/// The cadence's two counters as a restart RESUMES them, read off the feed's
/// entries above the last head's position (the module doc's RESUME FROM THE
/// FEED).
struct ResumedCadence {
    /// Entries whose testimony is not `"system"` — every commit landed since
    /// the head that was not the head's own; a bare entry, its testimony
    /// lost, counts.
    commits_since_head: u64,
    /// The head's own time: the recorded `time` of the LAST entry testifying
    /// `"system"` — the head's publish, or a later attempt's orphaned insert,
    /// either way the board's most recent head work — else the first entry
    /// above the position carrying a time (a witness no earlier than the
    /// head, so the hour fires no sooner than it is owed), else `None`:
    /// open-time.
    last_head_millis: Option<u64>,
}

/// RESUME FROM THE FEED: the cadence over the entries above the last head's
/// position, in position order, as [`Feed::entries_above`] hands them over.
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

/// RESUME-BY-READING: `H`'s latest member's recorded head, or `None` when
/// `H`'s trunk chain has no member yet (or its record is not a head this
/// build wrote — [`HeadRecord::parse`] — treated as no head, so the next
/// trigger writes a fresh one). The record is the atom at content position 1
/// of the trunk head, read off M5's point resolution and M4's value.
fn read_recorded_head(world: &World) -> Option<HeadRecord> {
    let h = head_document();
    let member = trunk_head(world.m3(), &h)?;
    let i_addr = world.m5().point(&member, &VPos::content(Nat::from(1u32)))?;
    HeadRecord::parse(world.content().value_at(i_addr.tumbler())?.as_bytes())
}

/// The staging draft's address — doc 3 of the system account, `1.1.0.1.0.3`:
/// the seed registers doc 1 and doc 2 ([`skep_namespace::M3State::genesis`]),
/// the system principal holds no key and has no session, so the head writer
/// is the only writer under the account and its first mint lands here by the
/// document chain's frontier. Pinned so a reopened writer can FIND the draft
/// (resume by reading) instead of minting a new private document per uptime.
fn staging_draft_address() -> Address {
    let t = Tumbler::new([1u32, 1, 0, 1, 0, 3].into_iter().map(Nat::from))
        .expect("a six-component sequence is nonempty");
    validate(t).expect("the staging draft 1.1.0.1.0.3 is T4-valid by construction")
}

/// The staging draft an earlier uptime minted, if any: [`staging_draft_address`]
/// when it is a registered, unpublished document — the only shape the head
/// writer ever gives it — else `None`, and the first head mints it.
fn find_staging_draft(world: &World) -> Option<Address> {
    let draft = staging_draft_address();
    let m3 = world.m3();
    (m3.is_registered_document(&draft) && !m3.published(&draft)).then_some(draft)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The schema's ONE card, both directions: a record renders in the
    /// schema's order with no whitespace and reads back as itself, `base`
    /// and `prev` present or absent. The two hashes of a `base` are distinct
    /// bytes, so a transposed pair cannot pass; and a record another format
    /// wrote is not this build's head.
    #[test]
    fn a_head_record_renders_in_schema_order_and_reads_back_as_itself() {
        let hex = |b: u8| hex_string(&[b; 32]);
        let full = HeadRecord {
            position: 7,
            chain: [0xab; 32],
            base: Some(CheckpointBase { seq: 4, chain: [0x01; 32], body_hash: [0x02; 32] }),
            prev: Some(CommittedPair { position: 3, chain: [0xcd; 32] }),
        };
        let bytes = full.to_bytes();
        assert_eq!(
            String::from_utf8(bytes.clone()).expect("utf-8"),
            format!(
                "{{\"type\":\"skep-head\",\"format\":\"{FORMAT_STAMP}\",\"position\":7,\
                 \"chain\":\"{}\",\"base\":{{\"seq\":4,\"chain\":\"{}\",\"body_hash\":\"{}\"}},\
                 \"prev\":{{\"position\":3,\"chain\":\"{}\"}}}}",
                hex(0xab),
                hex(0x01),
                hex(0x02),
                hex(0xcd),
            ),
        );
        assert_eq!(HeadRecord::parse(&bytes), Some(full));
        let first = HeadRecord { position: 1, chain: [0x0f; 32], base: None, prev: None };
        let first_bytes = first.to_bytes();
        assert_eq!(HeadRecord::parse(&first_bytes), Some(first), "the first head: base and prev null");
        let first_text = String::from_utf8(first_bytes).expect("utf-8");
        let foreign = first_text.replace(FORMAT_STAMP, "SKJ3");
        assert_eq!(HeadRecord::parse(foreign.as_bytes()), None, "a head another format wrote");
        let other_type = first_text.replace(RECORD_TYPE, "skep-tail");
        assert_eq!(HeadRecord::parse(other_type.as_bytes()), None, "a record of another type");
        // The reader admits EXACTLY what the writer emits: `hex_string` writes
        // lowercase and no sign, so another spelling of the same bytes — one a
        // radix parse would fold back to them — is not this build's record.
        let chain = hex(0x0f);
        for respelled in [chain.to_uppercase(), format!("+f{}", &chain[2..])] {
            let text = first_text.replace(&chain, &respelled);
            assert_eq!(HeadRecord::parse(text.as_bytes()), None, "a respelled hash: {respelled}");
        }
    }

    /// The clock seam holds EVERY reading — `u64::MAX`, the far-future value
    /// a test reaching for "the hour has certainly passed" writes first,
    /// included — and an unset clock reads the wall clock. A reading the seam
    /// accepted and then answered with the wall clock instead would leave a
    /// time-bound test passing or failing with the bound never consulted.
    #[test]
    fn the_clock_seam_holds_every_reading_and_an_unset_clock_reads_the_wall_clock() {
        let clock = Clock::new();
        assert!(
            clock.now_millis().abs_diff(wall_clock_millis()) < 60_000,
            "an unset clock reads the wall clock"
        );
        for fixed in [0, TIME_BOUND_MILLIS, u64::MAX] {
            clock.set_millis(fixed);
            assert_eq!(clock.now_millis(), fixed, "a fixed reading holds, whatever its value");
        }
    }
}
