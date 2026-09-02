//! The best-effort retry de-duplication cache (§7): a bounded, per-uptime
//! memo of committed-write acknowledgments keyed by [`IdemKey`] — the
//! client's `ReqId` confined to the session that committed under it.
//!
//! A hint, never a guarantee. It is in memory only, so a post-restart retry
//! re-executes (a duplicate, by design — ASN-0134 §A7), and it holds only
//! what a lost acknowledgment can duplicate: the [`CommittedAck`] of a write
//! that already committed. Rejections and read answers are not admissible —
//! the first must re-execute under a Reorder/Retry reissue, the second would
//! replay a stale snapshot — and the [`CommittedAck`] type is what makes them
//! inexpressible here rather than merely unwelcome.

use std::num::NonZeroUsize;

use lru::LruCache;
use parking_lot::Mutex;

use crate::op::{OpKind, ReqId};
use crate::response::CommittedAck;
use crate::session::SessionId;

/// The idempotency LRU's capacity, in the type [`LruCache`] demands — so
/// nonzero is proven where the number is written, not re-proven where it is
/// used.
// OPEN DECISION: the interface pins `Operation::new(stores)` with NO
// `idem_capacity` parameter, while the design (§7 / Core data model / Open
// build decision 3) calls for an explicit construction-time knob with "no
// implicit default". The interface is the higher authority for the public
// surface, so the knob is absent and this crate-fixed default bounds the LRU
// instead — surfaced in the build report as an interface↔design conflict.
const DEFAULT_IDEM_CAPACITY: NonZeroUsize = NonZeroUsize::new(1024).expect("1024 is nonzero");

/// The session-confined idempotency key (§7). A client's `ReqId` is unique
/// only WITHIN its session, so the session it committed under is half the
/// key's identity rather than a field beside it.
///
/// That confinement is what makes the step-(a) lookup in `execute` — which
/// runs BEFORE authentication — harmless (§7 item-4): a replay carrying
/// another session's `ReqId` builds a different key and simply misses, so no
/// memoized ack can cross from the principal that committed the write to one
/// that did not.
#[derive(Clone, PartialEq, Eq, Hash)]
struct IdemKey {
    session: SessionId,
    req: ReqId,
}

/// A memoized acknowledgment plus the op-kind that produced it. The tag lets
/// [`IdemCache::get`] miss on a `ReqId` reused across op-kinds, so a
/// wrong-shaped ack is never served.
#[derive(Clone)]
struct Cached {
    kind: OpKind,
    ack: CommittedAck,
}

/// The memo itself (§7). Bounded by [`DEFAULT_IDEM_CAPACITY`]; eviction is
/// LRU and costs only a re-execution, which is what "best effort" means
/// here.
///
/// Non-poisoning lock (§7): a panic while the cache is held must not break
/// `execute`'s Total contract.
pub(crate) struct IdemCache {
    entries: Mutex<LruCache<IdemKey, Cached>>,
}

impl IdemCache {
    pub(crate) fn new() -> IdemCache {
        IdemCache { entries: Mutex::new(LruCache::new(DEFAULT_IDEM_CAPACITY)) }
    }

    /// Memoize one committed-write acknowledgment under this session's key.
    /// Takes the `ReqId` because the key keeps it.
    pub(crate) fn put(&self, s: SessionId, id: ReqId, kind: OpKind, ack: CommittedAck) {
        self.entries.lock().put(IdemKey { session: s, req: id }, Cached { kind, ack });
    }

    /// The memoized acknowledgment this session committed under `id` for
    /// this op-kind. A foreign session misses on the key ([`IdemKey`]); a
    /// `ReqId` reused across op-kinds misses on the tag. Either way the
    /// request re-executes.
    pub(crate) fn get(&self, s: SessionId, id: &ReqId, kind: OpKind) -> Option<CommittedAck> {
        let mut g = self.entries.lock();
        let c = g.get(&IdemKey { session: s, req: id.clone() })?; // bumps LRU recency
        (c.kind == kind).then(|| c.ack.clone())
    }

    /// Drop every entry this session committed — the other half of retiring
    /// a binding (§6): a retired session leaves no memo behind. A linear
    /// sweep of the bounded cache.
    pub(crate) fn purge_session(&self, s: SessionId) {
        let mut g = self.entries.lock();
        let dead: Vec<IdemKey> =
            g.iter().filter(|(k, _)| k.session == s).map(|(k, _)| k.clone()).collect();
        for k in dead {
            g.pop(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use skep_address::{validate, Address, Nat, Tumbler};
    use skep_kernel::Seq;

    use super::*;

    fn a(comps: &[u32]) -> Address {
        let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty");
        validate(t).unwrap_or_else(|_| panic!("T4-valid test address"))
    }

    /// §7: the memo round-trips an ack keyed by [`IdemKey`] and op-kind-
    /// matched — a foreign session or a reused-across-kinds `ReqId` misses —
    /// and `purge_session` clears one session's entries only.
    #[test]
    fn confinement_and_purge() {
        let sessions = crate::session::Sessions::new();
        let cache = IdemCache::new();
        let s1 = sessions.open(skep_namespace::PrincipalId(1));
        let s2 = sessions.open(skep_namespace::PrincipalId(2));
        let id = ReqId(b"req-1".to_vec());
        cache.put(
            s1,
            id.clone(),
            OpKind::CreateNewDocument,
            CommittedAck::Addr { addr: a(&[1, 0, 1]), at: Seq(9) },
        );
        // The SAME id under a second session, deliberately: confinement is
        // what makes the two entries distinct.
        cache.put(
            s2,
            id.clone(),
            OpKind::Fork,
            CommittedAck::Addr { addr: a(&[1, 0, 2]), at: Seq(10) },
        );
        // Same session + kind: hit, rebuilt equal.
        match cache.get(s1, &id, OpKind::CreateNewDocument) {
            Some(CommittedAck::Addr { addr, at }) => {
                assert_eq!(addr, a(&[1, 0, 1]));
                assert_eq!(at, Seq(9));
            }
            _ => panic!("expected a memoized Addr ack"),
        }
        // Foreign session: miss on this session's key (cross-principal
        // confinement, item-4) — the same ReqId under s2 is a DIFFERENT
        // entry, and answers s2's own ack.
        assert!(cache.get(s2, &id, OpKind::CreateNewDocument).is_none());
        assert!(cache.get(s2, &id, OpKind::Fork).is_some());
        // Op-kind mismatch: miss (a wrong-shaped ack is never served).
        assert!(cache.get(s1, &id, OpKind::Fork).is_none());
        // Purge clears s1's entries and leaves s2's.
        cache.purge_session(s1);
        assert!(cache.get(s1, &id, OpKind::CreateNewDocument).is_none());
        assert!(cache.get(s2, &id, OpKind::Fork).is_some());
    }
}
