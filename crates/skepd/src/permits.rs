//! A counting permit pool — a try-acquire with no queue and no blocking,
//! whose guard returns its slot on drop — the ONE mechanism behind the
//! daemon's two bounded pools: the reconstruction budget (`history.rs`) and
//! the class-scan pool (`server/scan.rs`). A permit is a slot of the pool that
//! minted it, so neither bound can spend the other's.

use std::sync::atomic::{AtomicUsize, Ordering};

/// A pool of permits: a counting try-acquire with no queue and no blocking
/// — plain atomics, no new dependency. The guard returns its permit on
/// drop, early returns and panics included.
///
/// The bound behind
/// [`MAX_CONCURRENT_RECONSTRUCTIONS`](crate::history::MAX_CONCURRENT_RECONSTRUCTIONS),
/// and — as a second, separate instance — behind `server/scan.rs`'s
/// `MAX_CONCURRENT_CLASS_SCANS` (wire v7.9): one mechanism, two pools. A
/// permit belongs to the pool it came from, so the two bounds cannot spend
/// each other's slots.
#[derive(Debug)]
pub(crate) struct Permits {
    available: AtomicUsize,
}

/// One held permit; dropping it releases the slot in the pool that issued
/// it. Named rather than hidden behind an opaque `impl Drop`, so a caller
/// can store it, borrow it, and read what it is — the standing every guard
/// in `std` has, `#[must_use]` included: a permit taken and dropped in one
/// statement licenses nothing. Public only to be the return type of the
/// daemon's two test hooks, and `#[doc(hidden)]` for the same reason.
#[doc(hidden)]
#[derive(Debug)]
#[must_use = "a permit dropped at once returns its slot at once: bind it for as long as the \
              work it licenses runs"]
pub struct Permit<'a> {
    pool: &'a Permits,
}

impl Permits {
    /// A pool of `n` permits.
    pub(crate) fn new(n: usize) -> Permits {
        Permits { available: AtomicUsize::new(n) }
    }

    /// One permit, or `None` right now — never blocks. `#[must_use]` on the
    /// function as well as the type: an `Option` is no `#[must_use]` type, so
    /// the permit it carries would otherwise drop unremarked.
    #[must_use = "a permit dropped at once returns its slot at once"]
    pub(crate) fn try_acquire(&self) -> Option<Permit<'_>> {
        self.available
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .ok()
            .map(|_| Permit { pool: self })
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.pool.available.fetch_add(1, Ordering::Release);
    }
}
