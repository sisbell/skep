//! Reading the world as of a committed position (wire v3) — the whole
//! obligation on one card: the reconstruction budget, the throwaway kernel
//! a historical world is read through, and the `as_of` stamping that makes
//! the answer say which position it is OF.
//!
//! The mechanism is the engine's bounded replay (`Engine::world_at`):
//! checkpoint-or-genesis base plus journal fold, per call, uncached. That
//! is core-bound work, so [`History`] admits at most
//! [`MAX_CONCURRENT_RECONSTRUCTIONS`] at once and refuses the surplus
//! outright ([`Unavailable::Busy`]) rather than queueing — a worker parked
//! behind a replay is a worker lost to live traffic. The permit spans the
//! engine call alone: the read that follows runs on a detached `World` and
//! competes with nobody.
//!
//! [`Unavailable`] says why an answer cannot be given without knowing what
//! an HTTP status is; `server.rs` owns the one mapping onto the wire's
//! transport errors.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use skep_arrangement::Vstream;
#[cfg(feature = "observe")]
use skep_engine::observe::WorldDump;
use skep_engine::{Engine, HistoryError, World};
use skep_febe::{Operation, Request, Response, Stores};
use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelConfig, Seq};
use skep_links::LinkWriter;
use skep_namespace::{Namespace, PrincipalId};

/// Concurrent historical reconstructions (`Engine::world_at` behind
/// `/op-at` and `/dump?at`) allowed at once: each is a whole-checkpoint
/// deserialize plus journal fold, per call, uncached — two keeps history
/// panes serviceable without letting core-bound replay occupy the whole
/// worker pool.
pub(crate) const MAX_CONCURRENT_RECONSTRUCTIONS: usize = 2;

/// Why a historical answer is unavailable — the daemon's momentary
/// saturation, or the journal's own verdict on the position. Deliberately
/// free of HTTP: what a caller is owed for each is a wire decision.
#[derive(Debug)]
pub(crate) enum Unavailable {
    /// Every reconstruction permit is in use; the position may be perfectly
    /// good. Retryable, and the only variant that is.
    ///
    /// PRECEDENCE: the permit is taken before the journal is consulted, so
    /// this precedes every [`HistoryError`] — including M2's own published
    /// refusal order. A `Busy` answer therefore says NOTHING about whether
    /// `at` is a good position: a request naming one long past the head is
    /// told to retry, and only a retry that finds a free permit learns
    /// otherwise.
    Busy,
    /// The bounded replay refused: beyond the head, not a boundary,
    /// reclaimed, or the journal is unreadable. M2 fixes the order among
    /// these; [`Unavailable::Busy`] sits ahead of all of them.
    Journal(HistoryError),
}

/// The history surface: the reconstruction budget, and the two questions
/// asked of it.
#[derive(Debug)]
pub(crate) struct History {
    permits: ReconstructPermits,
}

impl History {
    pub fn new() -> History {
        History { permits: ReconstructPermits::new(MAX_CONCURRENT_RECONSTRUCTIONS) }
    }

    /// The world as of `at`, under one reconstruction permit — held across
    /// the engine call and released before the caller reads the world it
    /// gets back. `at` is not examined until a permit is in hand, so
    /// [`Unavailable::Busy`] precedes every journal verdict about it.
    pub fn world_at(&self, engine: &Engine, at: Seq) -> Result<World, Unavailable> {
        let Some(_permit) = self.permits.try_acquire() else {
            return Err(Unavailable::Busy);
        };
        engine.world_at(at).map_err(Unavailable::Journal)
    }

    /// The `WorldDump` of the world as of `at` — the same bounded replay
    /// [`History::read_at`] answers from, rendered as the engine renders its
    /// live dump. The pairing of a reconstructed world with the genesis
    /// config it must be read against lives here, with the reconstruction:
    /// it is a fact about how a historical world is read, not about HTTP,
    /// so `/dump`'s two arms each simply ask a collaborator for a dump.
    #[cfg(feature = "observe")]
    pub fn dump_at(&self, engine: &Engine, at: Seq) -> Result<WorldDump, Unavailable> {
        let world = self.world_at(engine, at)?;
        Ok(skep_engine::observe::dump(&world, engine.genesis_config()))
    }

    /// One already-classified READ frame answered as of `at`: reconstruct
    /// the world, run the frame against a throwaway M10 over it, and stamp
    /// the position the answer is OF. The world comes from
    /// [`History::world_at`] here and nowhere else, which is what
    /// discharges [`execute_read_on`]'s precondition on it.
    pub fn read_at(
        &self,
        engine: &Engine,
        at: Seq,
        req: Request,
    ) -> Result<Response, Unavailable> {
        let world = self.world_at(engine, at)?;
        let mut resp = execute_read_on(world, req);
        stamp_as_of(&mut resp, at);
        Ok(resp)
    }

    /// TEST HOOK (the `fuzz_support` standing: not a stable API): hold one
    /// permit exactly as an in-flight reconstruction does, or `None` when
    /// all [`MAX_CONCURRENT_RECONSTRUCTIONS`] are taken. Real
    /// reconstructions finish in milliseconds, so the integration tests pin
    /// the counter through this instead of racing the engine.
    pub fn try_hold_permit(&self) -> Option<ReconstructPermit<'_>> {
        self.permits.try_acquire()
    }
}

/// The bound behind [`MAX_CONCURRENT_RECONSTRUCTIONS`]: a counting
/// try-acquire with no queue and no blocking — plain atomics, no new
/// dependency. The guard returns its permit on drop, early returns and
/// panics included.
#[derive(Debug)]
struct ReconstructPermits {
    available: AtomicUsize,
}

/// One held permit; dropping it releases the slot. Named rather than
/// hidden behind an opaque `impl Drop`, so a caller can store it, borrow
/// it, and read what it is — the standing every guard in `std` has. Public
/// only to be the return type of the daemon's test hook, and
/// `#[doc(hidden)]` for the same reason.
#[doc(hidden)]
#[derive(Debug)]
pub struct ReconstructPermit<'a> {
    permits: &'a ReconstructPermits,
}

impl ReconstructPermits {
    fn new(n: usize) -> ReconstructPermits {
        ReconstructPermits { available: AtomicUsize::new(n) }
    }

    /// One permit, or `None` right now — never blocks.
    fn try_acquire(&self) -> Option<ReconstructPermit<'_>> {
        self.available
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .ok()
            .map(|_| ReconstructPermit { permits: self })
    }
}

impl Drop for ReconstructPermit<'_> {
    fn drop(&mut self) {
        self.permits.available.fetch_add(1, Ordering::Release);
    }
}

/// Run one already-classified READ frame against a historical world: a
/// throwaway in-memory M2 kernel rooted at that world, a throwaway M10 over
/// it, one `execute`. All the read semantics stay M10's and the stores' —
/// the daemon only assembles. The session is minted and retired up front
/// (the guest pattern): reads are principal-free, and even a misclassified
/// write would meet M10's own `Unauthenticated` wall rather than a store.
///
/// PRECONDITION: `world` is one `Engine::world_at` produced. That is what
/// discharges `Durability::InMemory`'s genesis obligation — this mode does
/// not LOAD, so `WorldState::rebuild_derived` never runs on the root, and
/// the world arrives with whatever derived hints it already carries. The
/// bounded replay has seeded its base through `rebuild_derived` and
/// maintained the hints across the fold, so the premise holds. A world
/// assembled any other way would be read through stale hints, and nothing
/// about the answer would look wrong.
fn execute_read_on(world: World, req: Request) -> Response {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
    };
    let kernel =
        Arc::new(Kernel::open(cfg, world).expect("in-memory open runs no recovery and cannot fail"));
    let febe = Operation::new(Box::new(HistoryStores { kernel }));
    let sid = febe.open_session(PrincipalId(u64::MAX));
    febe.close_session(sid);
    febe.execute(sid, req)
}

/// `Stores<World>` over the throwaway historical kernel — the same shape as
/// the engine's `EngineStores`, which is constructible only over the live
/// recovered kernel and so cannot serve here.
struct HistoryStores {
    kernel: Arc<Kernel<World>>,
}

impl Stores<World> for HistoryStores {
    fn kernel(&self) -> &Kernel<World> {
        &self.kernel
    }

    fn namespace(&self) -> Namespace<'_, World> {
        Namespace::new(&self.kernel)
    }

    fn vstream(&self) -> Vstream<'_, World> {
        Vstream::new(&self.kernel)
    }

    fn linkstore(&self) -> LinkWriter<'_, World> {
        LinkWriter::new(&self.kernel)
    }
}

/// Stamp the requested position as `as_of`: the throwaway kernel is rooted
/// at the historical world with its own seq at 0, so M10's snapshot-seq
/// stamping — correct live — must be overwritten with the position the
/// answer is OF. Purely mechanical; every read shape is listed, writes
/// cannot reach here, and rejections carry no `as_of` at history exactly as
/// they carry none live.
fn stamp_as_of(resp: &mut Response, at: Seq) {
    match resp {
        Response::Delivery { as_of, .. }
        | Response::SpanSet { as_of, .. }
        | Response::Addrs { as_of, .. }
        | Response::MaybeAddr { as_of, .. }
        | Response::Count { as_of, .. }
        | Response::Page { as_of, .. }
        | Response::Endsets { as_of, .. }
        | Response::Runs { as_of, .. }
        | Response::Bool { as_of, .. }
        | Response::LinkValue { as_of, .. }
        | Response::Follow { as_of, .. }
        | Response::Deletions { as_of, .. }
        | Response::Compare { as_of, .. }
        | Response::Orphans { as_of, .. }
        | Response::Claims { as_of, .. } => *as_of = at,
        Response::Ack { .. }
        | Response::AckAddr { .. }
        | Response::AckEdit { .. }
        | Response::Rejected(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    /// The counter is exact: [`MAX_CONCURRENT_RECONSTRUCTIONS`] acquires
    /// succeed, the next fails, and a drop returns exactly one slot.
    #[test]
    fn reconstruct_permits_account_exactly() {
        let permits = ReconstructPermits::new(MAX_CONCURRENT_RECONSTRUCTIONS);
        let first = permits.try_acquire().expect("permit 1 of 2");
        let second = permits.try_acquire().expect("permit 2 of 2");
        assert!(
            permits.try_acquire().is_none(),
            "the cap is exactly {MAX_CONCURRENT_RECONSTRUCTIONS} reconstructions"
        );
        drop(first);
        let third = permits.try_acquire().expect("a dropped permit reopens its slot");
        assert!(permits.try_acquire().is_none(), "still exactly one slot came back");
        drop(second);
        drop(third);
        let a = permits.try_acquire().expect("all slots return");
        let b = permits.try_acquire().expect("all slots return");
        drop((a, b));
    }

    /// Under real threads, at most [`MAX_CONCURRENT_RECONSTRUCTIONS`]
    /// holders exist at any instant — the invariant is asserted inside the
    /// hold, so any overshoot fails loudly regardless of scheduling.
    #[test]
    fn reconstruct_permits_bound_concurrent_holders() {
        let permits = ReconstructPermits::new(MAX_CONCURRENT_RECONSTRUCTIONS);
        let holding = AtomicUsize::new(0);
        let granted = AtomicUsize::new(0);
        thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for _ in 0..200 {
                        let Some(permit) = permits.try_acquire() else { continue };
                        let holders = holding.fetch_add(1, Ordering::AcqRel) + 1;
                        assert!(
                            holders <= MAX_CONCURRENT_RECONSTRUCTIONS,
                            "{holders} concurrent holders exceeds the budget of \
                             {MAX_CONCURRENT_RECONSTRUCTIONS}"
                        );
                        granted.fetch_add(1, Ordering::Relaxed);
                        std::hint::spin_loop();
                        holding.fetch_sub(1, Ordering::AcqRel);
                        drop(permit);
                    }
                });
            }
        });
        assert!(granted.load(Ordering::Relaxed) > 0, "some acquires must have succeeded");
    }

    /// `History`'s budget is the permits' budget: exhausting it through the
    /// public hook makes the next reconstruction request unavailable as
    /// `Busy`, and releasing one reopens exactly one slot.
    #[test]
    fn history_hands_out_exactly_the_reconstruction_budget() {
        let history = History::new();
        let held: Vec<_> = (0..MAX_CONCURRENT_RECONSTRUCTIONS)
            .map(|_| history.try_hold_permit().expect("a permit"))
            .collect();
        assert!(
            history.try_hold_permit().is_none(),
            "the budget is exactly {MAX_CONCURRENT_RECONSTRUCTIONS} reconstructions"
        );
        drop(held);
        assert!(history.try_hold_permit().is_some(), "released permits return to the budget");
    }
}
