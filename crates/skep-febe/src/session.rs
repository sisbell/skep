//! The ephemeral session→principal binding (§6): [`SessionId`] and the
//! [`Sessions`] table that mints, holds and retires them. M10's only
//! authoritative state, and authoritative only for the uptime — nothing here
//! is journaled, snapshotted or replayed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use skep_namespace::PrincipalId;

/// An M10-minted session handle (§6). The field is deliberately private:
/// ids come from [`Sessions::open`] alone, save [`SessionId::GUEST`], which
/// no `open` mints, and the transport injects them from the connection's
/// authenticated binding — a `SessionId` is never read off the wire (the §6
/// non-forgeability precondition), so nothing outside M10 constructs one.
///
/// `#[must_use]`: an id is the only handle on the binding it names, and
/// `OperationSurface::close_session` needs it, so dropping one leaves a
/// binding nothing can retire for the rest of the uptime.
#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SessionId(u64);

impl SessionId {
    /// THE GUEST — the one id a caller names without opening a session. No
    /// [`OperationSurface::open_session`] mints it, so it resolves to no
    /// principal for the life of every surface:
    /// [`OperationSurface::execute`] answers each read under it as the guest
    /// (the published documents alone) and refuses each write
    /// `Unauthenticated`. It is what a transport hands a request that
    /// presents no session.
    ///
    /// Naming it forges nothing: it carries none of a bound session's
    /// authority, and no write at all. Closing it is a no-op.
    ///
    /// [`OperationSurface::open_session`]: crate::OperationSurface::open_session
    /// [`OperationSurface::execute`]: crate::OperationSurface::execute
    pub const GUEST: SessionId = SessionId(0);
}

#[cfg(test)]
impl SessionId {
    /// An id a TEST picks rather than one `open` minted — for a test that
    /// needs a never-opened session no caller could name. The test picks a
    /// value past every id its surface has opened; `0` is refused, being
    /// [`SessionId::GUEST`], the one never-opened id a caller CAN name.
    pub(crate) fn unminted(n: u64) -> SessionId {
        assert_ne!(n, 0, "0 is `SessionId::GUEST`, which a caller names without a test hook");
        SessionId(n)
    }
}

/// Which principal each open session speaks for, and the counter that mints
/// the handles (§6). Ids are unique within one M10 uptime (reset on restart;
/// clients re-authenticate) and retired permanently by [`Sessions::close`] —
/// never reissued within the uptime.
///
/// Non-poisoning lock (§7): a panic while the map is held must not break
/// `execute`'s Total contract.
pub(crate) struct Sessions {
    bindings: Mutex<HashMap<SessionId, PrincipalId>>,
    next_id: AtomicU64,
}

impl Sessions {
    pub(crate) fn new() -> Sessions {
        // 0 is `SessionId::GUEST`, which no `open` mints: the counter starts
        // past it.
        Sessions { bindings: Mutex::new(HashMap::new()), next_id: AtomicU64::new(1) }
    }

    /// Record the binding and hand back a fresh id.
    pub(crate) fn open(&self, principal: PrincipalId) -> SessionId {
        let session = SessionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        self.bindings.lock().insert(session, principal);
        session
    }

    /// The principal this session speaks for — `None` once retired, and for
    /// an id that was never opened.
    pub(crate) fn principal_of(&self, session: SessionId) -> Option<PrincipalId> {
        self.bindings.lock().get(&session).copied()
    }

    /// Retire the binding. The id is dead for the rest of the uptime.
    pub(crate) fn close(&self, session: SessionId) {
        self.bindings.lock().remove(&session);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

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

    /// §6 under the concurrency the surface is shared across (§8): a transport
    /// opens sessions from every worker at once, and each id is still minted
    /// once and bound to the principal it was opened for. A counter read and
    /// written in two steps would hand two connections one id, the second
    /// binding overwriting the first — one connection then speaking for
    /// another's principal. The openers are released off one start line they
    /// are all already spinning on, so they open together rather than one
    /// after another as they are spawned; how often a racy counter collides
    /// is still the scheduler's to say, but correct code never fails here.
    #[test]
    fn sessions_opened_concurrently_are_distinct_and_each_keeps_its_principal() {
        const THREADS: u64 = 8;
        const OPENS: u64 = 10_000;
        let sessions = Sessions::new();
        let (ready, go) = (AtomicU64::new(0), AtomicBool::new(false));
        let opened: Vec<(SessionId, PrincipalId)> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..THREADS)
                .map(|t| {
                    let (sessions, ready, go) = (&sessions, &ready, &go);
                    scope.spawn(move || {
                        ready.fetch_add(1, Ordering::Release);
                        while !go.load(Ordering::Acquire) {
                            std::hint::spin_loop();
                        }
                        (0..OPENS)
                            .map(|i| {
                                let principal = PrincipalId(t * OPENS + i);
                                (sessions.open(principal), principal)
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            while ready.load(Ordering::Acquire) < THREADS {
                std::hint::spin_loop();
            }
            go.store(true, Ordering::Release);
            handles.into_iter().flat_map(|h| h.join().expect("no opener panics")).collect()
        });
        let ids: std::collections::HashSet<SessionId> = opened.iter().map(|(s, _)| *s).collect();
        assert_eq!(ids.len(), opened.len(), "two opens were handed one id");
        assert!(!ids.contains(&SessionId::GUEST), "no open mints the guest");
        for (session, principal) in opened {
            assert_eq!(
                sessions.principal_of(session),
                Some(principal),
                "{session:?} speaks for another principal"
            );
        }
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

    /// The guest is the one id no `open` mints: it resolves to no principal,
    /// and closing it retires nothing — every binding opened beside it stays.
    #[test]
    fn the_guest_is_never_minted_and_never_bound() {
        let sessions = Sessions::new();
        let opened: Vec<(SessionId, PrincipalId)> = (0..8)
            .map(|i| {
                let principal = PrincipalId(i);
                (sessions.open(principal), principal)
            })
            .collect();
        assert!(
            opened.iter().all(|(s, _)| *s != SessionId::GUEST),
            "no `open` mints the guest"
        );
        assert_eq!(sessions.principal_of(SessionId::GUEST), None, "the guest is bound to no one");

        sessions.close(SessionId::GUEST);
        for (s, principal) in opened {
            assert_eq!(sessions.principal_of(s), Some(principal), "closing the guest retires nothing");
        }
        assert_eq!(sessions.principal_of(SessionId::GUEST), None);
    }
}
