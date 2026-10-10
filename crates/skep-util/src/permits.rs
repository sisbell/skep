//! A counting permit pool — a try-acquire with no queue and no blocking,
//! whose guard returns its slot on drop — the ONE mechanism behind the
//! daemon's five bounded pools: the reconstruction budget (`history.rs`),
//! the class-scan pool (`server/scan.rs`), the fetch pool (`skep-media`'s
//! `serve.rs`), the upload pool (`skep-media`'s `lib.rs`) and the write pool
//! (the daemon's `server.rs`). A permit is a slot of the pool that minted
//! it, so no bound can spend another's.
//!
//! Beside it, THE EDGE TRACKER ([`EdgeTracker`]; `operations.md` §1.1 m12):
//! the once-per-episode memory of a bound that refuses — the first refusal
//! that meets it an edge, and the clearing an edge once the condition has
//! stood clear for a hold-down the holder names — so what a saturated pool,
//! a full stream budget, a spent nonce or a failing `accept` says on the
//! operator stream is two lines per episode and never one per request. One
//! type the five pools, the live-stream budget, the challenge store and the
//! accept loop each hold; the words are each holder's, a pool's being
//! [`PoolEdgeLine`]'s; the clock the hold-down is judged against is
//! [`edge_clock_now`], one reading the daemon's test seam can advance.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::notice::Class;

/// A pool of permits: a counting try-acquire with no queue and no blocking
/// — plain atomics, no new dependency. The guard returns its permit on
/// drop, early returns and panics included.
///
/// The bound behind `history.rs`'s `MAX_CONCURRENT_RECONSTRUCTIONS`, and —
/// as further, separate instances — behind `server/scan.rs`'s
/// `MAX_CONCURRENT_CLASS_SCANS` (wire v7.9), the fetch pool of `skep-media`'s
/// `serve.rs`, the upload pool of its `lib.rs` and the write pool of the
/// daemon's `server.rs` (`MAX_CONCURRENT_WRITES`): one mechanism, five
/// pools. A permit belongs to the pool it came from, so no bound can spend
/// another's slots.
#[derive(Debug)]
pub struct Permits {
    available: AtomicUsize,
}

/// One held permit; dropping it releases the slot in the pool that issued
/// it. Named rather than hidden behind an opaque `impl Drop`, so a caller
/// can store it, borrow it, and read what it is — the standing every guard
/// in `std` has, `#[must_use]` included: a permit taken and dropped in one
/// statement licenses nothing. `#[doc(hidden)]` because the one surface
/// beyond the pools that names it is the daemon's five test hooks, whose
/// return type it is; not a stable API.
#[doc(hidden)]
#[derive(Debug)]
#[must_use = "a permit dropped at once returns its slot at once: bind it for as long as the \
              work it licenses runs"]
pub struct Permit<'a> {
    pool: &'a Permits,
}

impl Permits {
    /// A pool of `n` permits.
    pub fn new(n: usize) -> Permits {
        Permits { available: AtomicUsize::new(n) }
    }

    /// One permit, or `None` right now — never blocks. `#[must_use]` on the
    /// function as well as the type: an `Option` is no `#[must_use]` type, so
    /// the permit it carries would otherwise drop unremarked.
    #[must_use = "a permit dropped at once returns its slot at once"]
    pub fn try_acquire(&self) -> Option<Permit<'_>> {
        self.available
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .ok()
            .map(|_| Permit { pool: self })
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.pool.available.fetch_add(1, Ordering::Release);
    }
}

// ── the edge tracker ─────────────────────────────────────────────────────

/// THE EDGE TRACKER (`operations.md` §1.1 m12; §4 rows 27 and 33; §6's
/// three rows): the memory behind an EDGE PAIR — the two lines a bound that
/// refuses says per EPISODE, and nothing per request. A holder tells it
/// each refusal and each admission with the instant of the act; it answers
/// the edge the act crossed, if any:
///
/// * [`Edge::Failure`] at the FIRST refusal — the request that first meets
///   the bound opens an episode; every later refusal inside it adds no
///   edge, is counted, and RESTARTS the hold-down;
/// * [`Edge::Landing`] at the first ADMISSION once the condition has stood
///   clear — no refusal — for the hold-down, which closes the episode and
///   carries its refusals counted; the next refusal opens a new one.
///
/// A refusal never lands: a landing says the condition is clear, and only
/// an act the bound admitted shows it so. So the second edge is judged at
/// the holder's next ADMITTED act after the hold-down, however late — on a
/// quiet holder it comes at that act and not before (the ops lanes record
/// §5.3, the challenge pair's property: judged at a mint). The hold-down is
/// why a pair cannot flap at exactly the load that matters — a permit
/// returns, a request is admitted, the next is refused — into a line per
/// request.
///
/// The tracker holds no words and no door: the holder renders its line
/// ([`PoolEdgeLine`] for a pool, the daemon's own types for the budget, the
/// challenge store and the accept loop) and says it through the classed
/// door it has — at the edge where its site holds one, or later, through
/// the queue ([`EdgeTracker::queue`], [`EdgeTracker::drain`]) a holder with
/// no door of its own leaves its edges on for the daemon to say in order.
/// The clock is the caller's: every judgement takes `now`, and the daemon's
/// holders read [`edge_clock_now`]. The hold-down is the holder's, one
/// constant for every pair of the daemon's (`EDGE_HOLD_DOWN`, `limits.rs`).
#[derive(Debug)]
pub struct EdgeTracker {
    hold_down: Duration,
    /// Whether an episode stands — read without the lock on every admission,
    /// so the hot path of a bound that is clear costs one load.
    open: AtomicBool,
    /// Whether an edge waits in the queue — read without the lock on every
    /// drain, so a request that crossed no edge costs one load.
    pending: AtomicBool,
    state: Mutex<EdgeState>,
}

/// The tracker's state under its lock.
#[derive(Debug)]
struct EdgeState {
    /// The episode that stands, or `None` while the condition is clear.
    episode: Option<Episode>,
    /// The edges crossed and not yet said, oldest first
    /// ([`EdgeTracker::queue`]).
    queued: Vec<Edge>,
}

/// One episode: the instant of its last refusal — what the hold-down is
/// measured from — and its refusals so far.
#[derive(Debug, Clone, Copy)]
struct Episode {
    last_refusal: Instant,
    refusals: u64,
}

/// An edge crossed: the one fact a holder turns into a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    /// The first refusal of an episode: the condition met.
    Failure,
    /// The condition stood clear for the hold-down and an admission found it
    /// so: the episode's end, with the refusals it held.
    Landing {
        /// The refusals the episode counted, the first included.
        refusals: u64,
    },
}

impl Edge {
    /// The class word the edge's line goes out under: `failure:` for the
    /// first edge, `landing:` for the second — the door's, never a holder's
    /// to spell.
    pub fn class(self) -> Class {
        match self {
            Edge::Failure => Class::Failure,
            Edge::Landing { .. } => Class::Landing,
        }
    }
}

impl EdgeTracker {
    /// A tracker over `hold_down`, no episode standing and nothing queued.
    pub fn new(hold_down: Duration) -> EdgeTracker {
        EdgeTracker {
            hold_down,
            open: AtomicBool::new(false),
            pending: AtomicBool::new(false),
            state: Mutex::new(EdgeState { episode: None, queued: Vec::new() }),
        }
    }

    /// The hold-down this tracker judges the second edge by.
    pub fn hold_down(&self) -> Duration {
        self.hold_down
    }

    /// A REFUSAL at `now`: [`Edge::Failure`] where it opens an episode, `None`
    /// inside one — the refusal counted and the hold-down restarted from
    /// `now` either way.
    #[must_use = "the edge crossed is a line owed: say it, or queue it"]
    pub fn refused(&self, now: Instant) -> Option<Edge> {
        let mut st = self.lock();
        match st.episode.as_mut() {
            Some(episode) => {
                episode.last_refusal = now;
                episode.refusals += 1;
                None
            }
            None => {
                st.episode = Some(Episode { last_refusal: now, refusals: 1 });
                self.open.store(true, Ordering::Release);
                Some(Edge::Failure)
            }
        }
    }

    /// An ADMISSION at `now`: [`Edge::Landing`] where an episode stands and
    /// its last refusal is a whole hold-down behind `now`, which closes it;
    /// `None` where none stands or the hold-down has not passed. A `now`
    /// before the last refusal reads as no time passed.
    #[must_use = "the edge crossed is a line owed: say it, or queue it"]
    pub fn admitted(&self, now: Instant) -> Option<Edge> {
        if !self.open.load(Ordering::Acquire) {
            return None;
        }
        let mut st = self.lock();
        let episode = st.episode?;
        if now.saturating_duration_since(episode.last_refusal) < self.hold_down {
            return None;
        }
        st.episode = None;
        self.open.store(false, Ordering::Release);
        Some(Edge::Landing { refusals: episode.refusals })
    }

    /// Leave `edge` — the answer of [`EdgeTracker::refused`] or
    /// [`EdgeTracker::admitted`] — on the queue for a later
    /// [`EdgeTracker::drain`], in order; nothing for `None`. The door of a
    /// holder that has none at its site: the daemon drains its holders'
    /// queues at the end of every request it routes and says each edge
    /// through its own classed door.
    pub fn queue(&self, edge: Option<Edge>) {
        if let Some(edge) = edge {
            self.lock().queued.push(edge);
            self.pending.store(true, Ordering::Release);
        }
    }

    /// Say every queued edge through `say`, oldest first, under the lock —
    /// so two threads draining at once cannot say one tracker's landing
    /// after the failure that followed it — and leave the queue empty.
    /// Returns at once, at the cost of one load, where nothing is queued.
    pub fn drain(&self, mut say: impl FnMut(Edge)) {
        if !self.pending.load(Ordering::Acquire) {
            return;
        }
        let mut st = self.lock();
        for edge in st.queued.drain(..) {
            say(edge);
        }
        self.pending.store(false, Ordering::Release);
    }

    /// The lock, poisoned or not: nothing under it is left half-done by an
    /// unwind — a field store, a push — and a line's memory fails no work.
    fn lock(&self) -> MutexGuard<'_, EdgeState> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// A POOL's TWO LINES (`operations.md` §1.1 m12), the ruled words: `the
/// {pool} pool is saturated` at the first edge, `the {pool} pool has room
/// again` at the second — and, for the one pool the ruling lets carry it
/// ([`PoolEdgeLine::counted`], the upload pool's), ` after {n} refusals`,
/// the episode's count. NOTHING ELSE ON A LINE: no count otherwise, no
/// path, query, principal, peer, position or reader (D9, read loose: a pool
/// saying "full" names no reader). The class word is the door's
/// ([`Edge::class`]). One rendering for the five pools, so the two crates
/// that say them cannot drift apart.
pub struct PoolEdgeLine<'a> {
    pool: &'a str,
    edge: Edge,
    counted: bool,
}

impl<'a> PoolEdgeLine<'a> {
    /// The line for `pool`'s `edge`, carrying no count: the read pools' and
    /// the write pool's form.
    pub fn new(pool: &'a str, edge: Edge) -> PoolEdgeLine<'a> {
        PoolEdgeLine { pool, edge, counted: false }
    }

    /// The line for `pool`'s `edge`, the landing carrying the episode's
    /// refusals: the upload pool's form, the one the ruling admits a count
    /// on.
    pub fn counted(pool: &'a str, edge: Edge) -> PoolEdgeLine<'a> {
        PoolEdgeLine { pool, edge, counted: true }
    }
}

impl fmt::Display for PoolEdgeLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.edge {
            Edge::Failure => write!(f, "the {} pool is saturated", self.pool),
            Edge::Landing { refusals } if self.counted => {
                write!(f, "the {} pool has room again after {refusals} refusals", self.pool)
            }
            Edge::Landing { .. } => write!(f, "the {} pool has room again", self.pool),
        }
    }
}

// ── the edge clock ───────────────────────────────────────────────────────

/// THE CLOCK SEAM's OFFSET: milliseconds added to every reading of
/// [`edge_clock_now`], zero for the life of a shipped daemon. One offset for
/// the process, so the eight pairs read one clock and the daemon's hook
/// ([`advance_edge_clock_ms`]) moves them together.
static EDGE_CLOCK_OFFSET_MS: AtomicU64 = AtomicU64::new(0);

/// The instant the daemon's holders judge an edge at: the monotonic clock,
/// plus the offset the daemon's test seam has advanced it by — nothing, in
/// a shipped daemon. Read at the act, by the holder, and handed to the
/// tracker: the tracker reads no clock of its own, so a holder with a clock
/// already (the challenge store, judging a nonce's time to live at the mint)
/// judges its edges by the same reading it judges the rest by.
pub fn edge_clock_now() -> Instant {
    let now = Instant::now();
    let offset = Duration::from_millis(EDGE_CLOCK_OFFSET_MS.load(Ordering::Relaxed));
    now.checked_add(offset).unwrap_or(now)
}

/// THE CLOCK SEAM: advance [`edge_clock_now`] by `ms` for every reader in
/// the process, from now on — the daemon's test hook's one call, so a suite
/// drives a hold-down through a seam and never a sleep. A shipped daemon
/// calls it nowhere; it is a function and not a feature-gated one because
/// this crate carries no feature, and the hook that reaches it is gated in
/// the daemon.
pub fn advance_edge_clock_ms(ms: u64) {
    EDGE_CLOCK_OFFSET_MS.fetch_add(ms, Ordering::Relaxed);
}

#[cfg(test)]
mod tests;
