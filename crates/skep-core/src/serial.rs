//! The write-serialization lock, the guard that proves it held, and its takes.

use std::sync::atomic::{AtomicU64, Ordering};

/// The write-serialization lock — what a [`SerialGuard`] is held over.
///
/// Beside the lock, its takes and waits since the open ([`SerialFigures`]):
/// what an operator reads the serialization point's load by, where nothing
/// else says it before the write pool refuses `write_busy`.
pub(crate) struct Serial {
    lock: parking_lot::Mutex<()>,
    /// Every take of the lock since the open.
    takes: AtomicU64,
    /// The takes that found the lock held by another writer.
    waits: AtomicU64,
}

impl Serial {
    pub(crate) fn new() -> Serial {
        Serial {
            lock: parking_lot::Mutex::new(()),
            takes: AtomicU64::new(0),
            waits: AtomicU64::new(0),
        }
    }

    /// Takes the lock — the one constructor of a [`SerialGuard`].
    ///
    /// The take is counted, and a take that finds the lock held is counted a
    /// wait before it blocks: a `try_lock` ahead of the lock, and one
    /// increment per take, two where it waits.
    pub(crate) fn lock(&self) -> SerialGuard<'_> {
        self.takes.fetch_add(1, Ordering::Relaxed);
        let guard = self.lock.try_lock().unwrap_or_else(|| {
            self.waits.fetch_add(1, Ordering::Release);
            self.lock.lock()
        });
        SerialGuard(guard)
    }

    /// Returns the takes and the waits since the open.
    ///
    /// A wait's increment releases and the waits' read acquires, ahead of the
    /// takes' read, so a reading holds no wait whose take it lacks.
    pub(crate) fn figures(&self) -> SerialFigures {
        let waits = self.waits.load(Ordering::Acquire);
        SerialFigures { takes: self.takes.load(Ordering::Relaxed), waits }
    }
}

/// The write-serialization guard's takes and waits, counted from the open.
///
/// Both counts only rise. A take is a write sequence
/// reaching the serialization point — a commit, or a refusal its admission
/// gave under the guard; a wait is a take that found another writer holding
/// it. An arrival finds the guard held about as often as it is held, so the
/// share of takes that waited is how busy the serialization point is, and a
/// share that climbs is the write path nearing its limit before the write
/// pool refuses `write_busy`. The counts are of writes alone, never of a
/// reader.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SerialFigures {
    /// The takes of the guard.
    pub takes: u64,
    /// The takes that waited for another writer to release it.
    pub waits: u64,
}

impl SerialFigures {
    /// Returns the takes and the waits since `earlier`, a reading before this.
    pub fn since(self, earlier: SerialFigures) -> SerialFigures {
        SerialFigures {
            takes: self.takes.saturating_sub(earlier.takes),
            waits: self.waits.saturating_sub(earlier.waits),
        }
    }
}

/// The write-serialization guard, newtyped so a function whose contract is
/// "under the serialization lock" names it in its arguments — the device
/// `auth/`'s `LockRead`/[`crate::auth::LockWrite`] already
/// are. A bare `MutexGuard<'_, ()>` is satisfied by a guard over ANY
/// `Mutex<()>`, so the parameter would say "some unit lock is held" where
/// the contract says "this one is" — unambiguous only while the crate holds
/// exactly one, in a daemon whose body cap already anticipates a second
/// write path (the media round's blob route) by name.
///
/// The honest limit is [`crate::commits::Commits::serial_lock`]'s, unchanged: the guard
/// proves the lock is held and proves nothing about where the caller's
/// snapshot came from.
///
/// `#[must_use]`, as `lock_api`'s own `MutexGuard` is — an attribute the
/// newtype does not inherit: a guard taken and dropped in one statement is a
/// lock released before the next line.
#[must_use = "if unused the serialization lock will immediately unlock"]
pub struct SerialGuard<'a>(#[allow(dead_code)] parking_lot::MutexGuard<'a, ()>);

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that a take counts a wait only where another writer holds it.
    ///
    /// A free take counts one take and no wait; a take made while another
    /// writer holds the guard counts one wait as well, before it blocks — so
    /// the holder releases once the waiter has counted, and the figures read
    /// after both are exact.
    #[test]
    fn a_take_counts_a_wait_only_where_another_writer_holds_the_guard() {
        let serial = Serial::new();
        drop(serial.lock());
        assert_eq!(serial.figures(), SerialFigures { takes: 1, waits: 0 }, "a free take");
        let first = serial.figures();
        let held = serial.lock();
        std::thread::scope(|s| {
            let waiter = s.spawn(|| drop(serial.lock()));
            while serial.figures().waits == 0 {
                std::thread::yield_now();
            }
            drop(held);
            waiter.join().expect("the waiter takes the guard once it is released");
        });
        assert_eq!(serial.figures(), SerialFigures { takes: 3, waits: 1 }, "one waited");
        assert_eq!(
            serial.figures().since(first),
            SerialFigures { takes: 2, waits: 1 },
            "the two takes since the first reading, one of them a wait"
        );
    }
}
