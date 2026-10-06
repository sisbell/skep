//! The credential path's idempotency memo (AUTH-3.40–3.42, AUTH-6.33–6.34):
//! process memory, never world state, purged with its session.

use std::collections::HashMap;

use skep_febe::{ReqId, SessionId};

use super::LockWrite;

/// Per-`(SessionId, ReqId)` memo of marshaled credential acks — skepd's
/// own, because M10's memo exposes no `recall` accessor in this workspace
/// (a report finding; the semantics are the pinned ones): the ORIGINAL
/// ack, byte-identical, no execution; KIND-BLIND on a hit; uptime-scoped;
/// consulted inside `credential_lock.write()` before the precheck; purged
/// with its session. Stores marshaled bytes at execute time (AUTH-7.20's
/// first horn).
pub(crate) struct CredMemo {
    /// Session → its acks. Nested rather than keyed `(SessionId, ReqId)`,
    /// so a recall BORROWS the id instead of cloning one to build a key
    /// it then throws away, and a purge is one removal instead of a walk
    /// over every session's entries.
    sessions: parking_lot::Mutex<HashMap<SessionId, HashMap<ReqId, Vec<u8>>>>,
}

impl CredMemo {
    pub fn new() -> CredMemo {
        CredMemo { sessions: parking_lot::Mutex::new(HashMap::new()) }
    }

    /// The ORIGINAL ack for this `(session, id)`, under the write guard it
    /// names in its arguments (AUTH-3.3). The guard is the obligation, not
    /// a decoration: AUTH-3.40/3.41 make the recall atomic with the
    /// precheck-and-execute it guards, so a recall outside the lock lets a
    /// concurrent credential write land between the miss and the precheck
    /// and the retry executes twice.
    pub fn recall(&self, _lock: &LockWrite<'_>, sid: SessionId, id: &ReqId) -> Option<Vec<u8>> {
        let sessions = self.sessions.lock();
        sessions.get(&sid)?.get(id).cloned()
    }

    /// Memoize one marshaled ack, under the write guard (AUTH-3.3) —
    /// reached through [`super::AuthState::commit_tail`], the credential
    /// path's committed tail.
    ///
    /// Takes the id BY VALUE: the caller already owns one — the frame is
    /// consumed by `execute`, so the id is cloned out ahead of that move —
    /// and this map keeps it, so a borrow here would only turn the
    /// caller's one clone into two.
    pub fn store(&self, _lock: &LockWrite<'_>, sid: SessionId, id: ReqId, ack: Vec<u8>) {
        self.sessions.lock().entry(sid).or_default().insert(id, ack);
    }

    /// A closed session takes its memo entries with it — the same
    /// obligation M10's own `close_session` discharges for its own memo.
    ///
    /// The ONE memo method that runs outside the credential write lock,
    /// and by necessity: it is reached from
    /// [`crate::server::Daemon::close_binding`], which the resolution path
    /// calls under the READ lock (the plain sequence), under the write lock
    /// (the credential sequence), and under neither (the route level) — so
    /// a write guard here would be unsatisfiable from the first and a
    /// self-deadlock from the second. Of the two interleavings against
    /// `store`, purge-then-store leaves an entry no live token names —
    /// benign for the ANSWER, since that `SessionId` is gone and nothing
    /// can recall it, and permanent for RETENTION, since this method is
    /// keyed by session and nothing else removes an entry; and
    /// store-then-purge merely loses a memoization for a session already
    /// dead, whose retry resolves Guest and never reaches
    /// [`CredMemo::recall`].
    pub fn purge(&self, sid: SessionId) {
        self.sessions.lock().remove(&sid);
    }
}
