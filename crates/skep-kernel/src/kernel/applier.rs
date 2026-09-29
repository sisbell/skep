//! The applier lock and its one door: [`ApplierLock::acquire`] refuses a
//! nested acquisition by the thread already holding it, and nothing outside
//! this file reaches the state it guards any other way — the lock's fields
//! are private here, and the guard it hands out is the only route to them.

use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::{Mutex, MutexGuard};

use super::ApplierState;

/// A process-unique, non-zero token per thread. `0` is issued to no thread, so
/// it doubles as "the applier is held by nobody".
fn applier_token() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    thread_local! {
        static TOKEN: u64 = NEXT.fetch_add(1, Ordering::Relaxed);
    }
    TOKEN.with(|token| *token)
}

/// The applier lock and the token of the thread holding it, kept as ONE value
/// because they must agree: the token is what lets [`ApplierLock::acquire`]
/// answer a nested acquisition as the precondition failure it is rather than
/// as the deadlock it would otherwise be. Held together so no write path can
/// reach the state without passing the door that refuses.
///
/// `Relaxed` suffices throughout: the only value ever compared is the reading
/// thread's OWN token, which no other thread stores, and a thread's own store
/// precedes its own load in program order. Other threads' stores are invisible
/// to the comparison because they can only be `0` or a token belonging to
/// somebody else.
pub(super) struct ApplierLock {
    state: Mutex<ApplierState>,
    /// The token of the thread currently inside the locked region, or `0` for
    /// none. Scoped per kernel, not per thread: one thread transacting on two
    /// DISTINCT kernels is honest input and must not be refused.
    owner: AtomicU64,
}

impl ApplierLock {
    pub(super) fn new(state: ApplierState) -> ApplierLock {
        ApplierLock {
            state: Mutex::new(state),
            owner: AtomicU64::new(0),
        }
    }

    /// Take the applier lock, refusing a nested acquisition by the thread
    /// that already holds it (§3). That is a caller's bug — the closure of a
    /// [`crate::Kernel::transact`] in progress calling `transact` on the same
    /// kernel — and it is answered as one, with a panic naming the broken
    /// obligation, rather than as the permanent wedge a non-reentrant lock
    /// would otherwise give: a wedge no operator can act on and no supervisor
    /// can tell from a slow fsync. The lock is reachable only through here, so
    /// no write path can take it without the refusal.
    pub(super) fn acquire(&self) -> Applier<'_> {
        let me = applier_token();
        assert!(
            self.owner.load(Ordering::Relaxed) != me,
            "transact is not reentrant: the closure called `transact` on this kernel, \
             which holds the applier lock for the whole of `f` (§3)"
        );
        let state = self.state.lock();
        self.owner.store(me, Ordering::Relaxed);
        Applier {
            owner: &self.owner,
            state,
        }
    }
}

/// The held applier lock. The owner is cleared BEFORE the lock is released (a
/// value's own `Drop::drop` runs before its fields drop), so no thread
/// observes a stale owner while another holds the lock.
pub(super) struct Applier<'k> {
    owner: &'k AtomicU64,
    state: MutexGuard<'k, ApplierState>,
}

impl Drop for Applier<'_> {
    fn drop(&mut self) {
        self.owner.store(0, Ordering::Relaxed);
    }
}

impl Deref for Applier<'_> {
    type Target = ApplierState;
    fn deref(&self) -> &ApplierState {
        &self.state
    }
}

impl DerefMut for Applier<'_> {
    fn deref_mut(&mut self) -> &mut ApplierState {
        &mut self.state
    }
}
