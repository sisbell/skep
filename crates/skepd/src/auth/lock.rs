//! The credential write lock (AUTH-3.1–3.3), and the guards that let a
//! function say in its signature which half of it the function runs under.

// ── the credential write lock (AUTH-3.1–3.3) ─────────────────────────────

/// The credential write lock: serializes credential-changing writes against
/// every other session-authenticated write. Writer-preferring by
/// requirement (AUTH-3.2); `parking_lot::RwLock` satisfies it (task-fair: a
/// waiting writer blocks new readers), which is the existence proof
/// AUTH-7.18 records — the REQUIREMENT binds, not the crate.
///
/// `auth/` holds exactly this one lock, so its guards are unqualified.
/// What the lock SCOPES is a different thing and wears a different word:
/// the refusal rules it serializes are the GATES (`board_state_admission`'s
/// two — the RES-26 gate once claimed, `pre_claim_gate` before — the
/// write-path check behind the first, and the precheck's ordered slots),
/// which is wire.md's term for a rule that refuses a write.
pub(crate) struct CredentialLock(parking_lot::RwLock<()>);

/// The read guard, newtyped so a function whose contract is "under the read
/// lock" names it in its arguments (AUTH-3.3).
pub(crate) struct LockRead<'a>(#[allow(dead_code)] parking_lot::RwLockReadGuard<'a, ()>);

/// The write guard — the credential path's.
pub(crate) struct LockWrite<'a>(#[allow(dead_code)] parking_lot::RwLockWriteGuard<'a, ()>);

impl CredentialLock {
    pub fn new() -> CredentialLock {
        CredentialLock(parking_lot::RwLock::new(()))
    }

    pub fn read(&self) -> LockRead<'_> {
        LockRead(self.0.read())
    }

    pub fn write(&self) -> LockWrite<'_> {
        LockWrite(self.0.write())
    }
}
