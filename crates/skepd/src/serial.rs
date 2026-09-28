//! The write-serialization lock and the guard that proves it held.

/// The write-serialization lock — what a [`SerialGuard`] is held over.
pub(crate) struct Serial(parking_lot::Mutex<()>);

impl Serial {
    pub(crate) fn new() -> Serial {
        Serial(parking_lot::Mutex::new(()))
    }

    /// Take the lock — the ONE constructor of a [`SerialGuard`].
    pub(crate) fn lock(&self) -> SerialGuard<'_> {
        SerialGuard(self.0.lock())
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
/// The honest limit is [`crate::write_path::WritePath::serial_lock`]'s, unchanged: the guard
/// proves the lock is held and proves nothing about where the caller's
/// snapshot came from.
///
/// `#[must_use]`, as `lock_api`'s own `MutexGuard` is — an attribute the
/// newtype does not inherit: a guard taken and dropped in one statement is a
/// lock released before the next line.
#[must_use = "if unused the serialization lock will immediately unlock"]
pub(crate) struct SerialGuard<'a>(#[allow(dead_code)] parking_lot::MutexGuard<'a, ()>);
