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
//! triggering write holds, each through the write path's QUIET door
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
//! first, memberless head), `draft` = the staging draft, `runs` = the new
//! atom's one run. The shot's source consult runs at
//! `visible_to(Caller::Principal(SYSTEM))`, never System's — the system
//! principal owns `H` and the draft, so it never withholds.
//!
//! THE CADENCE, on the write path with no clock thread — evaluated after
//! every write the write path's peer door runs ([`HeadWriter::after_commit`],
//! reached from `commit_under`): a head is due when (a) ≥ [`EVERY_COMMITS`]
//! commits that are NOT the writer's own have LANDED since the last head, OR
//! (b) the newest retained checkpoint's seq moved since the last head, OR (c)
//! ≥ [`MAX_INTERVAL_MILLIS`] have elapsed since the last head AND the
//! position moved. Never on a peer's request; never while the position has
//! not moved; never twice for one position (the head's own commits ride the
//! quiet door, which gives no head a turn, so they are neither counted nor
//! able to re-trigger). LANDED, not merely acked: `after_commit` is asked
//! after every write `commit_under` runs — an ack that committed nothing
//! this call (an idempotency replay answered from M10's memo, `emit`'s
//! incumbent ack) and a refusal included; the kernel's seq, not the answer,
//! says whether a commit landed, and one that did not counts nothing and
//! evaluates no trigger. RESUME BY READING: at open the writer reads `H`'s
//! latest member — its `position` and `chain` (the next head's `prev`; a head
//! is owed only once the position moves past it) and its `base` (trigger (b)'s
//! reference: a checkpoint taken after that head, before or after a restart,
//! is attested by the next head) — and finds the staging draft where it left
//! it; a crash between the insert and the shot leaves an orphan atom in the
//! draft and no member, and the next head's shot names the newer atom
//! (PUB-2.26's no-residue).
//!
//! RESUME FROM THE FEED (the chain's open items, item 2). The cadence's two
//! counters are seeded at open from the change feed's testimony about the
//! commits landed ABOVE the recorded head's position (`Feed::entries_above`),
//! so that PUB-6.65's "64 commits … have landed since the last head" and "one
//! hour has passed since the last head" are true of the BOARD across a
//! restart and not of the process: `commits_since_head` is the count of those
//! entries whose key is not `"system"` — a bare entry counts, conservative by
//! at most the head's own commits, so a head fires at most a few commits early
//! and never twice — and the hour's origin is the head's own last
//! `"system"`-keyed entry's recorded `time` (else the first entry above the
//! position carrying a time; else open-time). A BARE OR ABSENT SIDECAR FALLS
//! BACK to open-time seeding, the behaviour before the seed: the count starts
//! at zero and the hour is measured from open. The clock's domain is therefore
//! wall-clock unix milliseconds, the feed's own. D1 is kept — a gate reads
//! testimony to decide WHEN, and the head's bytes stay a pure function of the
//! root; AUTH-4.56's rewritable sidecar can move one head's timing within the
//! bounds the triggers already allow, never a duplicate and never a changed
//! content.
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

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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
use crate::codec::hex_string;
use crate::feed::Feed;
use crate::notice;
use crate::sidecar::CommitMeta;

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
/// because the resume READS it back ([`resume_seeds`]) to tell the head's
/// own commits from the ones the cadence counts.
pub(super) const SYSTEM_TESTIMONY: &str = "system";

/// The count bound (PUB-6.65, RES-304): a head is due once this many commits
/// that are not the writer's own have landed since the last head. 64 — at
/// that count the unheld tail a rewrite can hide in is ≤ 64 commits and the
/// heads are ~1/64 of the commits, ~19 bytes per user commit amortized (the
/// investigation's §3.3 table). Evaluated on the write path, never by a
/// thread — the posture the kernel's own checkpoint cadence takes, which
/// `server.rs` configures.
const EVERY_COMMITS: u64 = 64;

/// The time bound (PUB-6.65): a head is also due once this long has passed
/// since the last head AND the position has moved, so a slow board's head
/// does not go stale beyond an hour — evaluated LAZILY on the next commit,
/// never by a thread, and never writing a duplicate for a position that has
/// not moved.
const MAX_INTERVAL_MILLIS: u64 = 3_600_000; // one hour

/// The head writer's own clock, so the time bound (trigger (c)) is drivable in
/// tests through a seam rather than a `sleep`. In production `now_millis` is
/// WALL-CLOCK unix milliseconds — the domain the feed records commit times
/// in, so the resume can seed the last head's time from the head's own entry
/// (the module doc's RESUME FROM THE FEED); a wall clock that steps is
/// tolerated by the trigger's `saturating_sub`, and the cost of a step is one
/// head early or late by the step, never a duplicate. [`Clock::set_millis`]
/// overrides it with a fixed reading (the test seam, reached through
/// [`crate::Daemon::head_set_clock_millis`]), which a test therefore sets
/// RELATIVE TO the wall clock rather than at small numbers a seeded origin
/// would dwarf.
struct Clock {
    /// [`u64::MAX`] means "use the real wall clock"; any other value is a
    /// test override, held until changed.
    test_millis: AtomicU64,
}

impl Clock {
    fn new() -> Clock {
        Clock { test_millis: AtomicU64::new(u64::MAX) }
    }

    fn now_millis(&self) -> u64 {
        match self.test_millis.load(Ordering::Relaxed) {
            u64::MAX => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            fixed => fixed,
        }
    }

    fn set_millis(&self, millis: u64) {
        self.test_millis.store(millis, Ordering::Relaxed);
    }
}

/// The writer's mutable state — everything the trigger reads and the head
/// updates. Behind a [`Mutex`], but never held across a commit: the decision
/// is taken under it and it is dropped before any head write, which takes it
/// again for the staging draft ([`HeadWriter::ensure_draft`]); `parking_lot`'s
/// lock is not re-entrant, so holding it across the write would deadlock the
/// write on itself.
struct HeadState {
    /// The coordinate the most recent head NAMED (not the committed head):
    /// "the position moved" and "never twice for one position" read its
    /// position, and the next head's `prev` is it whole. `None` before the
    /// first head ever — read off `H` at open, not reset by a restart.
    last_head: Option<Coordinate>,
    /// The kernel's committed seq as of the writer's last look — at open, at
    /// each evaluation, and after the head's own commits — so a write that
    /// LANDED nothing (a refusal, an idempotency replay, an incumbent ack) is
    /// told from a commit: the seq did not pass this.
    last_seen_position: u64,
    /// Commits that are not the writer's own since the last head — trigger
    /// (a)'s count. Seeded at open from the feed's entries above the last
    /// head's position (the module doc's RESUME FROM THE FEED), so a board
    /// restarted every few commits still reaches [`EVERY_COMMITS`]; zero
    /// where the sidecar is bare or absent.
    commits_since_head: u64,
    /// The newest retained checkpoint's seq AS THE LAST HEAD NAMED IT (its
    /// `base.seq`; `None` where it named `null`, and before the first head) —
    /// trigger (b) fires when the newest retained checkpoint differs from it.
    /// Read off `H` at open, so a checkpoint that landed after the last head
    /// is attested by the next head whichever side of a restart it fell on.
    last_checkpoint_seq: Option<u64>,
    /// The clock reading at the last head — trigger (c)'s base, in wall-clock
    /// unix milliseconds. Seeded at open from the last head's own recorded
    /// `time` in the feed (RESUME FROM THE FEED), so after a reopen the hour
    /// is measured from the last head the BOARD wrote and not from this open;
    /// the head itself carries no timestamp (two heads of one board at one
    /// position are byte-identical), so a bare or absent sidecar leaves this
    /// at open-time, the one origin then on record.
    last_head_millis: u64,
    /// The staging draft — [`staging_draft_address`] once it is registered,
    /// found at open or minted at first need; `None` only on a board that has
    /// never written a head.
    staging_draft: Option<Address>,
}

/// A committed COORDINATE — a position and the chain AT it, the pair
/// `/health` serves live and `/chain?at` recomputes. What a head names, and
/// what its `prev` names of the head before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Coordinate {
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
    /// The previous head's coordinate, or `None` at the first.
    prev: Option<Coordinate>,
}

impl HeadRecord {
    /// The coordinate this head names — what the NEXT head's `prev` carries.
    fn coordinate(&self) -> Coordinate {
        Coordinate { position: self.position, chain: self.chain }
    }

    /// The record's bytes, hand-marshaled in SCHEMA order (`type`, `format`,
    /// `position`, `chain`, `base`, `prev`) with no whitespace — NOT the
    /// codec's sorted-key marshal, which would reorder them. `base` and
    /// `prev` are their objects or `null`; no `sig`, no timestamp (two heads
    /// of one board at one position are byte-identical).
    fn to_bytes(&self) -> Vec<u8> {
        use std::fmt::Write;
        let mut s = String::new();
        s.push_str("{\"type\":\"");
        s.push_str(RECORD_TYPE);
        s.push_str("\",\"format\":\"");
        s.push_str(FORMAT_STAMP);
        s.push_str("\",\"position\":");
        let _ = write!(s, "{}", self.position);
        s.push_str(",\"chain\":\"");
        s.push_str(&hex_string(&self.chain));
        s.push_str("\",\"base\":");
        match &self.base {
            Some(CheckpointBase { seq, chain, body_hash }) => {
                s.push_str("{\"seq\":");
                let _ = write!(s, "{seq}");
                s.push_str(",\"chain\":\"");
                s.push_str(&hex_string(chain));
                s.push_str("\",\"body_hash\":\"");
                s.push_str(&hex_string(body_hash));
                s.push_str("\"}");
            }
            None => s.push_str("null"),
        }
        s.push_str(",\"prev\":");
        match &self.prev {
            Some(Coordinate { position, chain }) => {
                s.push_str("{\"position\":");
                let _ = write!(s, "{position}");
                s.push_str(",\"chain\":\"");
                s.push_str(&hex_string(chain));
                s.push_str("\"}");
            }
            None => s.push_str("null"),
        }
        s.push('}');
        s.into_bytes()
    }

    /// A record THIS BUILD wrote, read back whole — `None` for anything else:
    /// not JSON, another `type`, another `format`, or a member missing or
    /// malformed. The inverse of [`HeadRecord::to_bytes`].
    fn parse(bytes: &[u8]) -> Option<HeadRecord> {
        let v: Value = serde_json::from_slice(bytes).ok()?;
        if v.get("type")?.as_str()? != RECORD_TYPE || v.get("format")?.as_str()? != FORMAT_STAMP {
            return None;
        }
        let coordinate = |v: &Value| -> Option<Coordinate> {
            Some(Coordinate {
                position: v.get("position")?.as_u64()?,
                chain: parse_hex32(v.get("chain")?.as_str()?)?,
            })
        };
        let Coordinate { position, chain } = coordinate(&v)?;
        let base = match v.get("base")? {
            Value::Null => None,
            base => Some(CheckpointBase {
                seq: base.get("seq")?.as_u64()?,
                chain: parse_hex32(base.get("chain")?.as_str()?)?,
                body_hash: parse_hex32(base.get("body_hash")?.as_str()?)?,
            }),
        };
        let prev = match v.get("prev")? {
            Value::Null => None,
            prev => Some(coordinate(prev)?),
        };
        Some(HeadRecord { position, chain, base, prev })
    }
}

/// The decision `after_commit` takes under the state lock and then acts on
/// without it: the record to publish, and the two readings the state takes
/// on once it lands.
struct Plan {
    record: HeadRecord,
    checkpoint_seq: Option<u64>,
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
    /// (PUB-6.65, I7 (a)): its recorded coordinate seeds `last_head`, so a
    /// head written after a restart carries the right `prev` and does not
    /// re-name a position already published; its `base.seq` seeds trigger
    /// (b)'s reference, so a checkpoint the last head did not name is
    /// attested by the next; and the staging draft is found where an earlier
    /// uptime minted it. All off ONE snapshot. And by reading the FEED (the
    /// module doc's RESUME FROM THE FEED): the entries above that position
    /// seed trigger (a)'s count and trigger (c)'s origin, a bare or absent
    /// sidecar falling back to zero and to open-time.
    pub(super) fn open(stores: EngineStores, feed: &Feed) -> HeadWriter {
        let clock = Clock::new();
        let now = clock.now_millis();
        let snap = stores.kernel().snapshot();
        let recorded = read_recorded_head(snap.world());
        let last_head = recorded.as_ref().map(HeadRecord::coordinate);
        let last_checkpoint_seq = recorded.as_ref().and_then(|r| r.base).map(|b| b.seq);
        let staging_draft = find_staging_draft(snap.world());
        // The feed is the daemon's testimony about its own commits: every
        // entry above the position the last head named landed since that
        // head, the head's own commits among them, keyed `SYSTEM_TESTIMONY`.
        // No head yet, and every retained entry is "since the last head".
        let seeds = resume_seeds(&feed.entries_above(last_head.map_or(0, |h| h.position)));
        HeadWriter {
            stores,
            state: Mutex::new(HeadState {
                last_head,
                last_seen_position: snap.seq().0,
                commits_since_head: seeds.commits_since_head,
                last_checkpoint_seq,
                last_head_millis: seeds.last_head_millis.unwrap_or(now),
                staging_draft,
            }),
            clock,
        }
    }

    /// The test seam behind [`crate::Daemon::head_set_clock_millis`]: fix the
    /// writer's clock at `millis`, so a test drives trigger (c) without a
    /// `sleep`. Not a stable API.
    pub(super) fn set_clock_millis(&self, millis: u64) {
        self.clock.set_millis(millis);
    }

    /// Called from [`WritePath::commit_under`] after every write that door
    /// runs, under the caller's serialization guard: if a commit LANDED — the
    /// kernel's seq, not the answer, is the arbiter — count it, and if a
    /// trigger is due, write the head. The head's own commits go through
    /// [`WritePath::commit_recorded`], which gives no head a turn, so they
    /// never reach here: neither counted nor able to re-trigger, by
    /// construction. The seq refresh at the end is what keeps the next landed
    /// commit from counting them.
    pub(super) fn after_commit(&self, wp: &WritePath, serial: &SerialGuard<'_>) {
        // Decide under the state lock, releasing it before any commit.
        let plan = {
            let mut st = self.state.lock();

            // The pair the head will name — the kernel's committed
            // (seq, chain) off ONE snapshot, before the head's own write opens.
            let snap = self.stores.kernel().snapshot();
            let position = snap.seq().0;

            // LANDED, not merely answered. `commit_under` asks after every
            // write it runs, and a write can answer without committing
            // anything this call: a refusal, an idempotency replay answered
            // from M10's memo, `emit`'s incumbent ack. The kernel's seq is
            // the arbiter — unmoved past the last look, nothing landed:
            // nothing to count, no trigger to evaluate (never while the
            // position has not moved).
            if position <= st.last_seen_position {
                return;
            }
            st.last_seen_position = position;
            st.commits_since_head = st.commits_since_head.saturating_add(1);

            let chain = snap.chain();
            let checkpoint = self.stores.kernel().newest_checkpoint();
            let checkpoint_seq = checkpoint.map(|(seq, _, _)| seq.0);
            let now = self.clock.now_millis();

            // Never twice for one position: a head sets `last_head` to the
            // coordinate it named, and a landed commit is always above it —
            // the literal guard, kept beside the seq gate above.
            let moved = st.last_head.map_or(position > 0, |last| position > last.position);
            if !moved {
                return;
            }
            let due = st.commits_since_head >= EVERY_COMMITS
                || (checkpoint_seq.is_some() && checkpoint_seq != st.last_checkpoint_seq)
                || now.saturating_sub(st.last_head_millis) >= MAX_INTERVAL_MILLIS;
            if !due {
                return;
            }

            // `base`: the newest retained checkpoint at or below the named
            // position, else null — the kernel's triple named here, in
            // `Kernel::newest_checkpoint`'s documented order, at the one place
            // it is unpacked. `prev`: the previous head's coordinate, null at
            // the first.
            let base = checkpoint.filter(|(seq, _, _)| seq.0 <= position).map(
                |(seq, chain_head, body_hash)| CheckpointBase {
                    seq: seq.0,
                    chain: chain_head,
                    body_hash,
                },
            );
            let record = HeadRecord { position, chain, base, prev: st.last_head };
            Plan { record, checkpoint_seq, now_millis: now }
        };

        let landed = self.write_head(wp, serial, &plan);
        let mut st = self.state.lock();
        if landed {
            st.last_head = Some(plan.record.coordinate());
            st.commits_since_head = 0;
            st.last_checkpoint_seq = plan.checkpoint_seq;
            st.last_head_millis = plan.now_millis;
        }
        // The head's own commits — a whole head's, or a refused one's partial
        // (the draft mint, the orphaned insert) — moved the seq: the next
        // evaluation measures "landed" from here, so they count nothing.
        st.last_seen_position = self.stores.kernel().snapshot().seq().0;
    }

    /// The two commits of one head: the record atom into the staging draft,
    /// then the publish shot minting the next member of `H`. `true` iff BOTH
    /// committed — a failed publish leaves the atom an orphan in the draft (the
    /// resume case), the state is not advanced, and the next commit retries.
    fn write_head(&self, wp: &WritePath, serial: &SerialGuard<'_>, plan: &Plan) -> bool {
        let Some(draft) = self.ensure_draft(wp, serial) else {
            return false;
        };
        let bytes = plan.record.to_bytes();

        // The next free content position of the draft, and the atom there.
        let next_ordinal = {
            let snap = self.stores.kernel().snapshot();
            snap.world().m5().content_count(&draft) + Nat::from(1u32)
        };
        let Some((atom_start, _)) = self.commit_insert(wp, serial, &draft, next_ordinal, bytes)
        else {
            return false;
        };

        // The shot: base is H's current trunk head (or H itself while
        // memberless), extent = that member's full content count so NOTHING is
        // carried — each member holds exactly its own record (0 at the first,
        // memberless head, PUB-6.65's "extent 0"). runs = the new atom alone.
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
                notice::line(format!(
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
        if let Some(draft) = self.state.lock().staging_draft.clone() {
            return Some(draft);
        }
        let account = system_account();
        let op = Op::CreateNewDocument { account: account.clone(), published: Some(false) };
        let meta = write_meta(&op)?.attributed(SYSTEM_TESTIMONY.to_string());
        let (draft, _) = self.run_commit(wp, serial, meta, move || {
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
            notice::line(format!(
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
    ) -> Option<(Address, Seq)> {
        let op = Op::Insert {
            doc: draft.clone(),
            at: VPos { subspace: Nat::from(1u32), ordinal },
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
    ) -> Option<(Address, Seq)> {
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

    /// One head commit through the write path's quiet door,
    /// [`WritePath::commit_recorded`] — recorded and announced like any
    /// write, giving no head a turn — as the system principal: run the
    /// driver inside the closure, hand the door the `AckAddr` its
    /// `record`/announce want, and return the committed `(address, seq)`. A
    /// driver refusal is logged and answered with a non-committing
    /// `Response` (recorded nowhere), so the head is skipped and the
    /// triggering write is untouched.
    fn run_commit(
        &self,
        wp: &WritePath,
        serial: &SerialGuard<'_>,
        meta: WriteMeta,
        run: impl FnOnce() -> Result<(Address, Seq), String>,
    ) -> Option<(Address, Seq)> {
        let mut captured: Option<(Address, Seq)> = None;
        let mut failure: Option<String> = None;
        let _ = wp.commit_recorded(serial, meta, || match run() {
            Ok((addr, at)) => {
                captured = Some((addr.clone(), at));
                Response::AckAddr { addr, at }
            }
            Err(e) => {
                failure = Some(e);
                // A no-op answer `record` returns None for: nothing recorded,
                // nothing announced. Dropped by this caller, never on the wire.
                Response::Bool { val: false, as_of: Seq(0) }
            }
        });
        if let Some(e) = failure {
            notice::line(format!("head writer: {e}; no head written this cycle"));
        }
        captured
    }
}

/// The cadence's two seeds, read off the feed's entries above the last head's
/// position (the module doc's RESUME FROM THE FEED).
struct ResumeSeeds {
    /// Entries whose key is not `"system"` — every commit landed since the
    /// head that was not the head's own; a bare entry, keyless, counts.
    commits_since_head: u64,
    /// The head's own time: the LAST `"system"`-keyed entry's recorded `time`
    /// — the head's publish, or a later attempt's orphaned insert, either way
    /// the board's most recent head work — else the first entry above the
    /// position carrying a time (a witness no earlier than the head, so the
    /// hour fires no sooner than it is owed), else `None`: open-time.
    last_head_millis: Option<u64>,
}

/// RESUME FROM THE FEED: the seeds over the entries above the last head's
/// position, in position order, as [`Feed::entries_above`] hands them over.
fn resume_seeds(above: &[(u64, CommitMeta)]) -> ResumeSeeds {
    let is_system = |meta: &CommitMeta| {
        matches!(meta, CommitMeta::Recorded { key: Some(key), .. } if key == SYSTEM_TESTIMONY)
    };
    let time_of = |meta: &CommitMeta| match meta {
        CommitMeta::Recorded { time, .. } => Some(*time),
        CommitMeta::Bare => None,
    };
    let commits_since_head = above.iter().filter(|(_, meta)| !is_system(meta)).count() as u64;
    let last_head_millis = above
        .iter()
        .rev()
        .find(|(_, meta)| is_system(meta))
        .and_then(|(_, meta)| time_of(meta))
        .or_else(|| above.iter().find_map(|(_, meta)| time_of(meta)));
    ResumeSeeds { commits_since_head, last_head_millis }
}

/// RESUME-BY-READING: `H`'s latest member's recorded head, or `None` when the
/// chain has no member yet (or its record is not a head this build wrote —
/// [`HeadRecord::parse`] — treated as no head, so the next trigger writes a
/// fresh one). The record is the atom at content position 1 of the trunk
/// head, read off M5's point resolution and M4's value.
fn read_recorded_head(world: &World) -> Option<HeadRecord> {
    let h = head_document();
    let member = trunk_head(world.m3(), &h)?;
    let i_addr = world.m5().point(&member, &VPos { subspace: Nat::from(1u32), ordinal: Nat::from(1u32) })?;
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

/// 64 lowercase hex characters into 32 bytes; `None` on any other shape.
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
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
            prev: Some(Coordinate { position: 3, chain: [0xcd; 32] }),
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
        let foreign = String::from_utf8(first_bytes).expect("utf-8").replace(FORMAT_STAMP, "SKJ3");
        assert_eq!(HeadRecord::parse(foreign.as_bytes()), None, "a head another format wrote");
    }
}
