//! The best-effort retry de-duplication cache (§7): a bounded, per-uptime
//! memo of committed-write acknowledgments keyed `(SessionId, ReqId)`.
//!
//! A hint, never a guarantee. It is in memory only, so a post-restart retry
//! re-executes (a duplicate, by design — ASN-0134 §A7), and it holds only
//! what a lost acknowledgment can duplicate: the [`Ack`] of a write that
//! already committed. Rejections and read answers are not admissible — the
//! first must re-execute under a Reorder/Retry reissue, the second would
//! replay a stale snapshot — and the [`Ack`] type is what makes them
//! inexpressible here rather than merely unwelcome.

use std::num::NonZeroUsize;

use lru::LruCache;
use parking_lot::Mutex;

use crate::op::{OpKind, ReqId};
use crate::response::Ack;
use crate::session::SessionId;

/// The idempotency LRU's capacity.
// OPEN DECISION: the interface pins `Operation::new(stores)` with NO
// `idem_capacity` parameter, while the design (§7 / Core data model / Open
// build decision 3) calls for an explicit construction-time knob with "no
// implicit default". The interface is the higher authority for the public
// surface, so the knob is absent and this crate-fixed default bounds the LRU
// instead — surfaced in the build report as an interface↔design conflict.
const DEFAULT_IDEM_CAPACITY: usize = 1024;

/// A memoized acknowledgment plus the op-kind that produced it. The tag lets
/// [`IdemCache::get`] miss on a `ReqId` reused across op-kinds, so a
/// wrong-shaped ack is never served.
#[derive(Clone)]
struct Cached {
    op: OpKind,
    ack: Ack,
}

/// The memo itself (§7). Bounded by [`DEFAULT_IDEM_CAPACITY`]; eviction is
/// LRU and costs only a re-execution, which is what "best effort" means
/// here.
///
/// Non-poisoning lock (§7): a panic while the cache is held must not break
/// `execute`'s Total contract.
pub(crate) struct IdemCache {
    entries: Mutex<LruCache<(SessionId, ReqId), Cached>>,
}

impl IdemCache {
    pub(crate) fn new() -> IdemCache {
        let cap = NonZeroUsize::new(DEFAULT_IDEM_CAPACITY).expect("capacity is a nonzero constant");
        IdemCache { entries: Mutex::new(LruCache::new(cap)) }
    }

    /// Memoize one committed-write acknowledgment under `(s, id)`.
    pub(crate) fn put(&self, s: SessionId, id: &ReqId, op: OpKind, ack: Ack) {
        self.entries.lock().put((s, id.clone()), Cached { op, ack });
    }

    /// The memoized acknowledgment for `(s, id)`, if it was committed under
    /// this session for this op-kind.
    ///
    /// The `(SessionId, ReqId)` key confines every hit to the session that
    /// committed the write — a replay under a different session simply
    /// misses, which is why the pre-authentication lookup in `execute` step
    /// (a) is harmless (§7 item-4). A `ReqId` reused across op-kinds misses
    /// too, and re-executes.
    pub(crate) fn get(&self, s: SessionId, id: &ReqId, op: OpKind) -> Option<Ack> {
        let mut g = self.entries.lock();
        let c = g.get(&(s, id.clone()))?; // foreign session misses; bumps LRU recency
        (c.op == op).then(|| c.ack.clone())
    }

    /// Drop every entry this session committed — the other half of retiring
    /// a binding (§6): a retired session leaves no memo behind. A linear
    /// sweep of the bounded cache.
    pub(crate) fn purge_session(&self, s: SessionId) {
        let mut g = self.entries.lock();
        let dead: Vec<(SessionId, ReqId)> =
            g.iter().filter(|(k, _)| k.0 == s).map(|(k, _)| k.clone()).collect();
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

    /// §7: the memo round-trips an ack keyed `(SessionId, ReqId)` and
    /// op-kind-matched — a foreign session or a reused-across-kinds `ReqId`
    /// misses — and `purge_session` clears one session's entries only.
    #[test]
    fn confinement_and_purge() {
        let sessions = crate::session::Sessions::new();
        let cache = IdemCache::new();
        let s1 = sessions.open(skep_namespace::PrincipalId(1));
        let s2 = sessions.open(skep_namespace::PrincipalId(2));
        let id = ReqId(b"req-1".to_vec());
        cache.put(s1, &id, OpKind::CreateNewDocument, Ack::Addr { addr: a(&[1, 0, 1]), at: Seq(9) });
        cache.put(s2, &id, OpKind::Fork, Ack::Addr { addr: a(&[1, 0, 2]), at: Seq(10) });
        // Same session + kind: hit, rebuilt equal.
        match cache.get(s1, &id, OpKind::CreateNewDocument) {
            Some(Ack::Addr { addr, at }) => {
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
