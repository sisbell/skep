//! The ephemeral session→principal binding (§6): [`SessionId`], the
//! [`Sessions`] table that binds, holds and retires them, and the one counter
//! every table in the process mints them from. The bindings are M10's only
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
/// An id names a binding on the surface that minted it and on no other. Every
/// surface in the process mints from ONE counter, so no two surfaces ever
/// mint the same id, and an id presented to a surface that did not mint it is
/// one that surface never opened: it resolves to no principal there — a read
/// under it is answered as the guest, a write refused `Unauthenticated` — and
/// closing it there retires nothing. [`SessionId::GUEST`] alone means the
/// same on every surface.
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
    /// value its own surface has not opened: a table holds only the ids it
    /// minted, so no other table's minting can bind it there. `0` is refused,
    /// being [`SessionId::GUEST`], the one never-opened id a caller CAN name.
    pub(crate) fn unminted(n: u64) -> SessionId {
        assert_ne!(n, 0, "0 is `SessionId::GUEST`, which a caller names without a test hook");
        SessionId(n)
    }
}

/// The one counter every [`Sessions`] table in the process mints from (§6).
/// A static and not a field of the table: a counter per table would hand two
/// tables the same numbers, and each would then answer for the other's ids
/// with bindings of its own. It starts past 0, which is [`SessionId::GUEST`]
/// and no `open` mints, and only moves forward, so no id is minted twice in
/// the uptime and no table ever binds an id another minted.
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

/// Which principal each open session speaks for (§6). Its ids come from
/// [`NEXT_SESSION`], so they are unique across every table in the process for
/// the uptime (reset on restart; clients re-authenticate), the table holds
/// only the ids it minted itself, and each is retired permanently by
/// [`Sessions::close`] — never reissued within the uptime.
///
/// Non-poisoning lock (§7): a panic while the map is held must not break
/// `execute`'s Total contract.
pub(crate) struct Sessions {
    bindings: Mutex<HashMap<SessionId, PrincipalId>>,
}

impl Sessions {
    pub(crate) fn new() -> Sessions {
        Sessions { bindings: Mutex::new(HashMap::new()) }
    }

    /// Record the binding under a fresh id from the process's one counter,
    /// and hand the id back.
    pub(crate) fn open(&self, principal: PrincipalId) -> SessionId {
        let session = SessionId(NEXT_SESSION.fetch_add(1, Ordering::Relaxed));
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
    /// after close, and a never-opened id unbound — one the process's counter
    /// is nowhere near, since every table in the test process draws from it.
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
        assert_eq!(sessions.principal_of(SessionId(u64::MAX)), None);
    }

    /// §6: an id names a binding on the table that minted it and on no
    /// other. Every table draws from the process's one counter, so an id
    /// another table minted is one this table never opened: it resolves to no
    /// principal here, and closing it here retires nothing. Two fresh tables
    /// are the case that matters — each one's FIRST id — since a counter per
    /// table would hand both the same number, and each would then answer for
    /// the other's id with its own binding.
    #[test]
    fn an_id_another_table_minted_is_unbound_here() {
        let (here, elsewhere) = (Sessions::new(), Sessions::new());
        let mine = here.open(PrincipalId(1));
        let theirs = elsewhere.open(PrincipalId(2));
        assert_ne!(mine, theirs, "two tables never mint one id");
        assert_eq!(here.principal_of(theirs), None, "another table's id is bound to no one here");
        here.close(theirs);
        assert_eq!(here.principal_of(mine), Some(PrincipalId(1)), "closing it retired nothing");
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
