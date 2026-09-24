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
//! DURABLE record.
//!
//! HOW IT LANDS. Per head, two commits under the SAME serialization lock the
//! triggering write holds, each through [`WritePath::commit_under`] with
//! testimony `"system"`: (1) one `insert` of the head record atom into a
//! private STAGING DRAFT (minted ONCE under the system account, `published:
//! false`, and reused — across restarts too: it is [`staging_draft_address`],
//! doc 3 of the system account, the one document the system principal ever
//! mints, and a reopened writer finds it registered rather than minting
//! another; the head reaches `H` and that draft and NO other document), then
//! (2) one `publish` shot minting the next member of `H`'s trunk chain —
//! `base` = `H`'s current trunk head with its extent set to that member's full
//! content count (so NOTHING is carried and each member holds exactly its own
//! record; 0 at the first, memberless head), `draft` = the staging draft,
//! `runs` = the new atom's one run. The shot's source consult runs at
//! `visible_to(Caller::Principal(SYSTEM))`, never System's — the system
//! principal owns `H` and the draft, so it never withholds.
//!
//! THE CADENCE, on the write path with no clock thread — evaluated where a
//! committing write records its position ([`HeadWriter::after_commit`],
//! reached from `commit_under`): a head is due when (a) ≥ `every_commits`
//! commits that are NOT the writer's own have LANDED since the last head, OR
//! (b) the newest retained checkpoint's seq moved since the last head, OR (c) ≥
//! `max_interval_millis` have elapsed since the last head AND the position
//! moved. Never on a peer's request; never while the position has not moved;
//! never twice for one position (the [`writing`](HeadWriter) guard excludes the
//! head's own two commits from the count and from re-triggering). LANDED, not
//! merely acked: `commit_under` also records an ack that committed nothing this
//! call — an idempotency replay answered from M10's memo, `emit`'s incumbent
//! ack — and those reach `after_commit` too; the kernel's seq, not the ack,
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

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::Mutex;
use serde_json::Value;
use skep_address::{validate, Address, Nat, Tumbler};
use skep_arrangement::{trunk_head, Base, Caller, Deposit, HasM5, Run, Shot, ShotRun, VPos};
use skep_content::{HasContent, Val};
use skep_engine::types::head_document;
use skep_engine::{EngineStores, World};
use skep_febe::{Op, Response, Stores};
use skep_kernel::Seq;
use skep_namespace::{system_account, HasM3, SYSTEM_PRINCIPAL};

use crate::codec::hex_string;
use crate::notice;
use crate::write_path::{write_meta, SerialGuard, WritePath};

/// The head record's `format` member — the journal stamp in force (`SKJ3`),
/// which names the hash and the byte format the `chain` value was computed
/// under, so a newer daemon reading an older head knows which chain it belongs
/// to. Not a bump: SKJ3/SKC3 stand (PUB-6.65, the golden regenerated under the
/// same stamp).
const FORMAT_STAMP: &str = "SKJ3";

/// The head writer's own clock, so the time bound (trigger (c)) is drivable in
/// tests through a seam rather than a `sleep`. In production `now_millis` is
/// monotonic wall-time since open; [`Clock::set_millis`] overrides it with a
/// fixed reading (the test seam, reached through
/// [`crate::Daemon::head_set_clock_millis`]).
struct Clock {
    start: Instant,
    /// [`u64::MAX`] means "use the real monotonic clock"; any other value is a
    /// test override, held until changed.
    test_millis: AtomicU64,
}

impl Clock {
    fn new() -> Clock {
        Clock { start: Instant::now(), test_millis: AtomicU64::new(u64::MAX) }
    }

    fn now_millis(&self) -> u64 {
        match self.test_millis.load(Ordering::Relaxed) {
            u64::MAX => self.start.elapsed().as_millis() as u64,
            fixed => fixed,
        }
    }

    fn set_millis(&self, millis: u64) {
        self.test_millis.store(millis, Ordering::Relaxed);
    }
}

/// The writer's mutable state — everything the trigger reads and the head
/// updates. Behind a [`Mutex`], but never held across a commit: the decision
/// is taken under it, then it is dropped before any head write, so the head's
/// own re-entrant `after_commit` (short-circuited by [`HeadWriter::writing`]
/// before it would lock) can never deadlock against it.
struct HeadState {
    /// The `position` the most recent head NAMED (not the committed head), so
    /// "the position moved" and "never twice for one position" both read this.
    /// `None` before the first head ever — read off `H` at open, not reset by
    /// a restart.
    last_position: Option<u64>,
    /// That head's `chain`, carried into the NEXT head's `prev`.
    last_chain: [u8; 32],
    /// The kernel's committed seq as of the writer's last look — at open, at
    /// each evaluation, and after the head's own commits — so an ack that
    /// LANDED nothing (an idempotency replay, an incumbent ack) is told from a
    /// commit: the seq did not pass this.
    last_seen_position: u64,
    /// Commits that are not the writer's own since the last head (or open) —
    /// trigger (a)'s count.
    commits_since_head: u64,
    /// The newest retained checkpoint's seq AS THE LAST HEAD NAMED IT (its
    /// `base.seq`; `None` where it named `null`, and before the first head) —
    /// trigger (b) fires when the newest retained checkpoint differs from it.
    /// Read off `H` at open, so a checkpoint that landed after the last head
    /// is attested by the next head whichever side of a restart it fell on.
    last_checkpoint_seq: Option<u64>,
    /// The clock reading at the last head (or open) — trigger (c)'s base. The
    /// clock is this uptime's, so after a reopen the hour is measured from
    /// open: the head carries no timestamp (two heads of one board at one
    /// position are byte-identical), so no better origin is on record.
    last_head_millis: u64,
    /// The staging draft — [`staging_draft_address`] once it is registered,
    /// found at open or minted at first need; `None` only on a board that has
    /// never written a head.
    staging_draft: Option<Address>,
}

/// The RAII hold on [`HeadWriter::writing`]: set for the head's own commits and
/// cleared on every exit from the head write — a refusal, an early return, an
/// unwind — so no failure can leave the flag set and the board silently
/// headless for the rest of the uptime (I11 (c), PUB-5.75).
struct Writing<'a>(&'a AtomicBool);

impl<'a> Writing<'a> {
    fn hold(flag: &'a AtomicBool) -> Writing<'a> {
        flag.store(true, Ordering::Release);
        Writing(flag)
    }
}

impl Drop for Writing<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// What `H`'s latest member records, read at open: the pair the next head's
/// `prev` carries and the base seq trigger (b) measures against.
struct RecordedHead {
    position: u64,
    chain: [u8; 32],
    base_seq: Option<u64>,
}

/// The decision `after_commit` takes under the state lock and then acts on
/// without it.
struct Plan {
    position: u64,
    chain: [u8; 32],
    base: Option<(u64, [u8; 32], [u8; 32])>,
    prev: Option<(u64, [u8; 32])>,
    checkpoint_seq: Option<u64>,
    now_millis: u64,
}

/// The head writer, owned by [`WritePath`]: its own handle on the engine's one
/// kernel (an [`EngineStores`] clone — the same `Arc<Kernel>`), the mutable
/// state, the re-entrancy guard, the clock, and the two cadence constants.
pub(crate) struct HeadWriter {
    stores: EngineStores,
    state: Mutex<HeadState>,
    /// Set while the head's OWN two commits run, so the `after_commit` they
    /// re-enter returns before it evaluates a trigger or counts a commit —
    /// checked lock-free, ahead of the state lock, so the recursion never
    /// touches the mutex.
    writing: AtomicBool,
    clock: Clock,
    every_commits: u64,
    max_interval_millis: u64,
}

impl HeadWriter {
    /// Open the writer over `stores`, RESUMING by reading `H`'s latest member
    /// (PUB-6.65, I7 (a)): its recorded `(position, chain)` seed
    /// `last_position`/`last_chain`, so a head written after a restart carries
    /// the right `prev` and does not re-name a position already published; its
    /// `base.seq` seeds trigger (b)'s reference, so a checkpoint the last head
    /// did not name is attested by the next; and the staging draft is found
    /// where an earlier uptime minted it. All off ONE snapshot.
    pub(crate) fn open(
        stores: EngineStores,
        every_commits: u64,
        max_interval_millis: u64,
    ) -> HeadWriter {
        let clock = Clock::new();
        let now = clock.now_millis();
        let snap = stores.kernel().snapshot();
        let recorded = read_recorded_head(snap.world());
        let (last_position, last_chain, last_checkpoint_seq) = match recorded {
            Some(RecordedHead { position, chain, base_seq }) => (Some(position), chain, base_seq),
            None => (None, [0u8; 32], None),
        };
        let staging_draft = find_staging_draft(snap.world());
        HeadWriter {
            stores,
            state: Mutex::new(HeadState {
                last_position,
                last_chain,
                last_seen_position: snap.seq().0,
                commits_since_head: 0,
                last_checkpoint_seq,
                last_head_millis: now,
                staging_draft,
            }),
            writing: AtomicBool::new(false),
            clock,
            every_commits,
            max_interval_millis,
        }
    }

    /// The test seam behind [`crate::Daemon::head_set_clock_millis`]: fix the
    /// writer's clock at `millis`, so a test drives trigger (c) without a
    /// `sleep`. Not a stable API.
    pub(crate) fn set_clock_millis(&self, millis: u64) {
        self.clock.set_millis(millis);
    }

    /// Evaluated where a committing write records its position (called from
    /// [`WritePath::commit_under`] under the caller's serialization guard):
    /// count the commit, and if a trigger is due, write the head. The head's
    /// OWN commits re-enter here and take the [`HeadWriter::writing`]
    /// short-circuit, so they are never counted and never re-trigger.
    pub(crate) fn after_commit(&self, wp: &WritePath, serial: &SerialGuard<'_>, _committed: Seq) {
        if self.writing.load(Ordering::Acquire) {
            return; // the head's own insert/publish — not a peer commit
        }
        // Decide under the state lock, releasing it before any commit.
        let plan = {
            let mut st = self.state.lock();

            // The pair the head will name — the kernel's committed
            // (seq, chain) off ONE snapshot, before the head's own write opens.
            let snap = self.stores.kernel().snapshot();
            let position = snap.seq().0;

            // LANDED, not merely acked. `commit_under` reaches here for every
            // ack it records, and an ack can carry a position that committed
            // nothing this call: an idempotency replay answered from M10's
            // memo, `emit`'s incumbent ack. The kernel's seq is the arbiter —
            // unmoved past the last look, nothing landed: nothing to count, no
            // trigger to evaluate (never while the position has not moved).
            if position <= st.last_seen_position {
                return;
            }
            st.last_seen_position = position;
            st.commits_since_head = st.commits_since_head.saturating_add(1);

            let chain = snap.chain();
            let checkpoint = self.stores.kernel().newest_checkpoint();
            let checkpoint_seq = checkpoint.map(|(s, _, _)| s.0);
            let now = self.clock.now_millis();

            // Never twice for one position: a head sets last_position to the
            // pair it named, and a landed commit is always above it — the
            // literal guard, kept beside the seq gate above.
            let moved = st.last_position.map_or(position > 0, |lp| position > lp);
            if !moved {
                return;
            }
            let due = st.commits_since_head >= self.every_commits
                || (checkpoint_seq.is_some() && checkpoint_seq != st.last_checkpoint_seq)
                || now.saturating_sub(st.last_head_millis) >= self.max_interval_millis;
            if !due {
                return;
            }

            // `base`: the newest retained checkpoint at or below the named
            // position, else null. `prev`: the previous head's pair, null at
            // the first.
            let base = checkpoint
                .filter(|(s, _, _)| s.0 <= position)
                .map(|(s, c, b)| (s.0, c, b));
            let prev = st.last_position.map(|lp| (lp, st.last_chain));
            Plan { position, chain, base, prev, checkpoint_seq, now_millis: now }
        };

        // Held for the head's own commits and released on EVERY exit below —
        // an unwind included — so no outcome leaves the board headless.
        let _writing = Writing::hold(&self.writing);
        let landed = self.write_head(wp, serial, &plan);
        let mut st = self.state.lock();
        if landed {
            st.last_position = Some(plan.position);
            st.last_chain = plan.chain;
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
        let bytes = marshal_head(plan.position, &plan.chain, plan.base, plan.prev);

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
        let h = head_document().clone();
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
        let meta = write_meta(&op)?.attributed("system".to_string());
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
        let meta = write_meta(&op)?.attributed("system".to_string());
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
        let meta = write_meta(&op)?.attributed("system".to_string());
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

    /// One head commit through [`WritePath::commit_under`] as the system
    /// principal: run the driver inside the closure, hand `commit_under` the
    /// `AckAddr` its `record`/announce want, and return the committed
    /// `(address, seq)`. A driver refusal is logged and answered with a
    /// non-committing `Response` (recorded nowhere), so the head is skipped and
    /// the triggering write is untouched.
    fn run_commit(
        &self,
        wp: &WritePath,
        serial: &SerialGuard<'_>,
        meta: crate::write_path::WriteMeta,
        run: impl FnOnce() -> Result<(Address, Seq), String>,
    ) -> Option<(Address, Seq)> {
        let mut captured: Option<(Address, Seq)> = None;
        let mut failure: Option<String> = None;
        let _ = wp.commit_under(serial, meta, || match run() {
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

/// The `skep-head` record's bytes, hand-marshaled in SCHEMA order (`type`,
/// `format`, `position`, `chain`, `base`, `prev`) with no whitespace — NOT the
/// codec's sorted-key marshal, which would reorder them. `base` and `prev` are
/// their objects or `null`; no `sig`, no timestamp (two heads of one board at
/// one position are byte-identical).
fn marshal_head(
    position: u64,
    chain: &[u8; 32],
    base: Option<(u64, [u8; 32], [u8; 32])>,
    prev: Option<(u64, [u8; 32])>,
) -> Vec<u8> {
    use std::fmt::Write;
    let mut s = String::new();
    s.push_str("{\"type\":\"skep-head\",\"format\":\"");
    s.push_str(FORMAT_STAMP);
    s.push_str("\",\"position\":");
    let _ = write!(s, "{position}");
    s.push_str(",\"chain\":\"");
    s.push_str(&hex_string(chain));
    s.push_str("\",\"base\":");
    match base {
        Some((seq, ch, bh)) => {
            s.push_str("{\"seq\":");
            let _ = write!(s, "{seq}");
            s.push_str(",\"chain\":\"");
            s.push_str(&hex_string(&ch));
            s.push_str("\",\"body_hash\":\"");
            s.push_str(&hex_string(&bh));
            s.push_str("\"}");
        }
        None => s.push_str("null"),
    }
    s.push_str(",\"prev\":");
    match prev {
        Some((pos, ch)) => {
            s.push_str("{\"position\":");
            let _ = write!(s, "{pos}");
            s.push_str(",\"chain\":\"");
            s.push_str(&hex_string(&ch));
            s.push_str("\"}");
        }
        None => s.push_str("null"),
    }
    s.push('}');
    s.into_bytes()
}

/// RESUME-BY-READING: `H`'s latest member's recorded head, or `None` when the
/// chain has no member yet (or its record cannot be read as a head — treated
/// as no head, so the next trigger writes a fresh one). The record is the atom
/// at content position 1 of the trunk head, read off M5's point resolution and
/// M4's value.
fn read_recorded_head(world: &World) -> Option<RecordedHead> {
    let h = head_document();
    let member = trunk_head(world.m3(), h)?;
    let i_addr = world.m5().point(&member, &VPos { subspace: Nat::from(1u32), ordinal: Nat::from(1u32) })?;
    let bytes = world.content().value_at(i_addr.tumbler())?.as_bytes().to_vec();
    parse_head(&bytes)
}

/// A head record's `position`, `chain` and `base.seq` (`None` for `base:
/// null`), parsed from its atom bytes — `None` if it is not a well-formed
/// `skep-head` (a foreign atom, or bytes a future format wrote).
fn parse_head(bytes: &[u8]) -> Option<RecordedHead> {
    let v: Value = serde_json::from_slice(bytes).ok()?;
    let position = v.get("position")?.as_u64()?;
    let chain = parse_hex32(v.get("chain")?.as_str()?)?;
    let base_seq = match v.get("base")? {
        Value::Null => None,
        base => Some(base.get("seq")?.as_u64()?),
    };
    Some(RecordedHead { position, chain, base_seq })
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
