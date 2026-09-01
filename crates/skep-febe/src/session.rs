//! The ephemeral session→principal binding (§6): [`SessionId`] and the
//! [`Sessions`] table that mints, holds and retires them. M10's only
//! authoritative state, and authoritative only for the uptime — nothing here
//! is journaled, snapshotted or replayed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use skep_namespace::PrincipalId;

/// An M10-minted session handle (§6). The field is deliberately private:
/// ids come from [`Sessions::open`] alone, and the transport injects them
/// from the connection's authenticated binding — a `SessionId` is never read
/// off the wire (the §6 non-forgeability precondition), so nothing outside
/// M10 constructs one.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SessionId(pub(crate) u64);

/// Which principal each open session speaks for, and the counter that mints
/// the handles (§6). Ids are unique within one M10 uptime (reset on restart;
/// clients re-authenticate) and retired permanently by [`Sessions::close`] —
/// never reissued within the uptime.
///
/// Non-poisoning lock (§7): a panic while the map is held must not break
/// `execute`'s Total contract.
pub(crate) struct Sessions {
    bound: Mutex<HashMap<SessionId, PrincipalId>>,
    next: AtomicU64,
}

impl Sessions {
    pub(crate) fn new() -> Sessions {
        Sessions { bound: Mutex::new(HashMap::new()), next: AtomicU64::new(1) }
    }

    /// Record the binding and hand back a fresh id.
    pub(crate) fn open(&self, principal: PrincipalId) -> SessionId {
        let s = SessionId(self.next.fetch_add(1, Ordering::Relaxed));
        self.bound.lock().insert(s, principal);
        s
    }

    /// The principal this session speaks for — `None` once retired, and for
    /// an id that was never opened.
    pub(crate) fn principal_of(&self, s: SessionId) -> Option<PrincipalId> {
        self.bound.lock().get(&s).copied()
    }

    /// Retire the binding. The id is dead for the rest of the uptime.
    pub(crate) fn close(&self, s: SessionId) {
        self.bound.lock().remove(&s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §6: distinct ids per open, the binding readable while open and gone
    /// after close, and a never-opened id unbound.
    #[test]
    fn ids_are_distinct_and_bindings_retire() {
        let sessions = Sessions::new();
        let s1 = sessions.open(PrincipalId(1));
        let s2 = sessions.open(PrincipalId(2));
        assert_ne!(s1, s2);
        assert_eq!(sessions.principal_of(s1), Some(PrincipalId(1)));
        assert_eq!(sessions.principal_of(s2), Some(PrincipalId(2)));
        sessions.close(s1);
        assert_eq!(sessions.principal_of(s1), None);
        assert_eq!(sessions.principal_of(s2), Some(PrincipalId(2)));
        assert_eq!(sessions.principal_of(SessionId(9999)), None);
    }

    /// A retired id is never reissued: the counter only moves forward.
    #[test]
    fn a_retired_id_is_never_reissued() {
        let sessions = Sessions::new();
        let s1 = sessions.open(PrincipalId(1));
        sessions.close(s1);
        for _ in 0..4 {
            assert_ne!(sessions.open(PrincipalId(1)), s1);
        }
    }
}
