//! The retry memo (§7): a bounded, per-uptime, best-effort memo of
//! committed-write acknowledgments keyed by [`MemoKey`] — the client's
//! `ReqId` confined to the session that committed under it.
//!
//! A hint, never a guarantee. It is in memory only, so a post-restart retry
//! re-executes (a duplicate, by design — ASN-0134 §A7); a session's entries
//! are swept when its binding retires, of those present when the sweep runs
//! ([`RetryMemo::purge_session`]); and it holds only what a lost
//! acknowledgment can duplicate: the [`CommittedAck`] of a write that already
//! committed. Rejections and read answers are not admissible —
//! the first must re-execute under a Reorder/Retry reissue, the second would
//! replay a stale snapshot — and the [`CommittedAck`] type is what makes them
//! inexpressible here rather than merely unwelcome.
//!
//! What it deduplicates is a SEQUENTIAL client's reissue — a retry sent after
//! the original completed and its acknowledgment was lost. It recognizes a
//! reissue by session, id and op-kind alone; that the reissue is the same
//! request is the client's word, which nothing here checks ([`ReqId`] states
//! the obligation). Between concurrent requests it offers nothing: `execute`
//! reads the memo at step (a) and writes it at step (d) with the whole
//! dispatch in between, so two requests in flight at once under one
//! `(session, id, kind)` both miss and both execute, and `execute` invites
//! exactly that concurrency (§8). Nothing here reserves a key for an operation
//! still running. Nor can the absence be pinned by a test: the interleaving is
//! nondeterministic, so an assertion that both commit would be flaky and one
//! that either may is vacuous.
//!
//! That admissibility rule is the memo's whole shape, so this is not a
//! general per-session key/value store and offers no opaque `recall`/`store`
//! pair: entries are engine acknowledgments, typed as such. A transport that
//! must memoize something else — a credential frame's ack, say — holds its own
//! memo, under its own bound, for a lifecycle it owns.

use std::num::NonZeroUsize;

use lru::LruCache;
use parking_lot::Mutex;

use crate::request::{OpKind, ReqId, MAX_REQ_ID_BYTES};
use crate::response::CommittedAck;
use crate::session::SessionId;

/// The memo's key (§7): the client's `ReqId` confined to the session that
/// committed under it. A `ReqId` is unique only WITHIN its session, so the
/// session is half the key's identity rather than a field beside it.
///
/// That confinement is what makes the step-(a) lookup in `execute` — which
/// runs BEFORE authentication — harmless (§7 item-4): a replay carrying
/// another session's `ReqId` builds a different key and simply misses, so no
/// memoized ack can cross from the principal that committed the write to one
/// that did not.
#[derive(Clone, PartialEq, Eq, Hash)]
struct MemoKey {
    session: SessionId,
    id: ReqId,
}

/// A memoized acknowledgment plus the op-kind that produced it. The tag lets
/// [`RetryMemo::get`] miss on a `ReqId` reused across op-kinds, so a
/// wrong-shaped ack is never served.
#[derive(Clone)]
struct TaggedAck {
    kind: OpKind,
    ack: CommittedAck,
}

/// The memo itself (§7). Bounded on both axes: the capacity its constructor
/// is handed — the design's construction-time knob with no implicit default
/// (§7, Open build decision 3), so this crate keeps no figure of its own and
/// the daemon supplies its pin — entries, each keyed by at most
/// [`MAX_REQ_ID_BYTES`] of client-chosen key, beside one acknowledgment of at
/// most two store-minted addresses, sized by what they acknowledge. Eviction
/// is LRU and costs only a re-execution, which is what "best effort" means
/// here.
///
/// Non-poisoning lock (§7): a panic while the memo is held must not break
/// `execute`'s Total contract.
pub(crate) struct RetryMemo {
    entries: Mutex<LruCache<MemoKey, TaggedAck>>,
}

impl RetryMemo {
    /// A memo of `capacity` entries, in the type [`LruCache`] demands — so
    /// nonzero is proven where the number is written, at the caller that
    /// chose it, and never re-proven here.
    pub(crate) fn new(capacity: NonZeroUsize) -> RetryMemo {
        RetryMemo { entries: Mutex::new(LruCache::new(capacity)) }
    }

    /// Memoize one committed-write acknowledgment under this session's key.
    /// Takes the `ReqId` because the key keeps it — which is why an id past
    /// [`MAX_REQ_ID_BYTES`] is declined here rather than truncated or
    /// admitted: the key's bytes are the second factor of the memo's key
    /// retention bill, and this is the check that bounds them for every
    /// caller, transport-parsed or hand-assembled.
    ///
    /// Declining is not a silence the never-silent contract forbids: that
    /// contract is about answering an operation, and the operation is
    /// answered either way. The memo is best-effort by construction (it
    /// declines on eviction and on restart already), so an oversized key
    /// costs exactly what those cost — a re-execution on retry.
    pub(crate) fn put(&self, session: SessionId, id: ReqId, kind: OpKind, ack: CommittedAck) {
        if id.0.len() > MAX_REQ_ID_BYTES {
            return;
        }
        self.entries.lock().put(MemoKey { session, id }, TaggedAck { kind, ack });
    }

    /// The memoized acknowledgment this session committed under `id` for
    /// this op-kind. A foreign session misses on the key ([`MemoKey`]); a
    /// `ReqId` reused across op-kinds misses on the tag. Either way the
    /// request re-executes.
    ///
    /// The lookup builds an owned key, so it clones `id` — outside the lock,
    /// which every write's steps (a) and (d) take — and an id past
    /// [`MAX_REQ_ID_BYTES`] misses without being cloned at all, since
    /// [`RetryMemo::put`] never admits one.
    pub(crate) fn get(&self, session: SessionId, id: &ReqId, kind: OpKind) -> Option<CommittedAck> {
        if id.0.len() > MAX_REQ_ID_BYTES {
            return None;
        }
        let key = MemoKey { session, id: id.clone() };
        let mut entries = self.entries.lock();
        let tagged = entries.get(&key)?; // bumps LRU recency
        (tagged.kind == kind).then(|| tagged.ack.clone())
    }

    /// Drop the entries this session has committed under as of now — the
    /// other half of retiring a binding (§6). A linear sweep of the bounded
    /// memo.
    ///
    /// The sweep sees what the memo holds when it runs. A request already
    /// past its step-(a) lookup in `execute` may [`RetryMemo::put`] its ack
    /// afterwards, and that entry then lives until eviction: one ack of a
    /// write that session itself committed, replayable only by presenting the
    /// retired id again, and authorizing nothing, since `close_session`
    /// retires the binding before calling this.
    pub(crate) fn purge_session(&self, session: SessionId) {
        let mut entries = self.entries.lock();
        let dead: Vec<MemoKey> =
            entries.iter().filter(|(k, _)| k.session == session).map(|(k, _)| k.clone()).collect();
        for k in dead {
            entries.pop(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use skep_address::{validate, Address, Nat, Tumbler};
    use skep_kernel::Seq;

    use super::*;

    fn addr(comps: &[u32]) -> Address {
        let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty");
        validate(t).unwrap_or_else(|_| panic!("T4-valid test address"))
    }

    /// A memo of `capacity` entries — the figure each test chooses, as the
    /// daemon chooses its own.
    fn memo_of(capacity: usize) -> RetryMemo {
        RetryMemo::new(NonZeroUsize::new(capacity).expect("a test capacity is nonzero"))
    }

    /// §7: the memo round-trips an ack keyed by [`MemoKey`] and op-kind-
    /// matched — a foreign session or a reused-across-kinds `ReqId` misses —
    /// and `purge_session` clears one session's entries only.
    #[test]
    fn an_entry_is_confined_to_its_session_and_kind_and_dies_with_the_session() {
        let sessions = crate::session::Sessions::new();
        let memo = memo_of(8);
        let s1 = sessions.open(skep_namespace::PrincipalId(1));
        let s2 = sessions.open(skep_namespace::PrincipalId(2));
        let id = ReqId(b"req-1".to_vec());
        memo.put(
            s1,
            id.clone(),
            OpKind::CreateNewDocument,
            CommittedAck::Addr { addr: addr(&[1, 0, 1]), at: Seq(9) },
        );
        // The SAME id under a second session, deliberately: confinement is
        // what makes the two entries distinct.
        memo.put(
            s2,
            id.clone(),
            OpKind::Fork,
            CommittedAck::Addr { addr: addr(&[1, 0, 2]), at: Seq(10) },
        );
        // Same session + kind: hit, rebuilt equal.
        match memo.get(s1, &id, OpKind::CreateNewDocument) {
            Some(CommittedAck::Addr { addr: replayed, at }) => {
                assert_eq!(replayed, addr(&[1, 0, 1]));
                assert_eq!(at, Seq(9));
            }
            _ => panic!("expected a memoized Addr ack"),
        }
        // Foreign session: miss on this session's key (cross-principal
        // confinement, item-4) — the same ReqId under s2 is a DIFFERENT
        // entry, and answers s2's own ack.
        assert!(memo.get(s2, &id, OpKind::CreateNewDocument).is_none());
        assert!(memo.get(s2, &id, OpKind::Fork).is_some());
        // Op-kind mismatch: miss (a wrong-shaped ack is never served).
        assert!(memo.get(s1, &id, OpKind::Fork).is_none());
        // Purge clears s1's entries and leaves s2's.
        memo.purge_session(s1);
        assert!(memo.get(s1, &id, OpKind::CreateNewDocument).is_none());
        assert!(memo.get(s2, &id, OpKind::Fork).is_some());
    }

    /// §7: the memo's OTHER bound. A key is retained for the life of its
    /// entry, so the key bill is (capacity × key bytes) and both factors are
    /// bounded here: a key past [`MAX_REQ_ID_BYTES`] is declined, one exactly
    /// at the bound is memoized, and declining costs a re-execution — the
    /// same thing eviction costs.
    #[test]
    fn an_oversized_key_is_not_memoized() {
        let sessions = crate::session::Sessions::new();
        let memo = memo_of(8);
        let s = sessions.open(skep_namespace::PrincipalId(1));

        let at_cap = ReqId(vec![b'k'; MAX_REQ_ID_BYTES]);
        memo.put(s, at_cap.clone(), OpKind::Delete, CommittedAck::At { at: Seq(1) });
        assert!(
            memo.get(s, &at_cap, OpKind::Delete).is_some(),
            "a key at the bound is an ordinary key"
        );

        let over = ReqId(vec![b'k'; MAX_REQ_ID_BYTES + 1]);
        memo.put(s, over.clone(), OpKind::Delete, CommittedAck::At { at: Seq(2) });
        assert!(
            memo.get(s, &over, OpKind::Delete).is_none(),
            "a key past the bound is never retained, so a retry re-executes"
        );
    }

    /// §7: the lookup holds the same bound. An id past [`MAX_REQ_ID_BYTES`]
    /// misses before its key is built — so no lookup clones more than the
    /// bound — and it misses even against an entry planted past `put`'s own
    /// check, which is what shows the refusal is the lookup's and not merely
    /// the absence `put` leaves.
    #[test]
    fn an_oversized_lookup_misses_before_its_key_is_built() {
        let sessions = crate::session::Sessions::new();
        let memo = memo_of(8);
        let s = sessions.open(skep_namespace::PrincipalId(1));
        let over = ReqId(vec![b'k'; MAX_REQ_ID_BYTES + 1]);
        memo.entries.lock().put(
            MemoKey { session: s, id: over.clone() },
            TaggedAck { kind: OpKind::Delete, ack: CommittedAck::At { at: Seq(1) } },
        );
        assert!(
            memo.get(s, &over, OpKind::Delete).is_none(),
            "a key the memo never admits is never looked up"
        );
    }

    /// §7 (op-D5): the memo is BOUNDED at the capacity its constructor was
    /// handed — here two, so the bound is met at the third entry — and what
    /// it drops when it overflows is the least recently used entry. A
    /// [`RetryMemo::get`] is a use, so the ack a client just replayed
    /// outlives one nobody has asked for. The same bound through the front
    /// door's own constructor is `tests/it/idempotency.rs`'s.
    #[test]
    fn the_memo_is_bounded_and_evicts_least_recently_used() {
        let sessions = crate::session::Sessions::new();
        let cap = 2;
        let memo = memo_of(cap);
        let s = sessions.open(skep_namespace::PrincipalId(1));
        let id = |i: usize| ReqId(i.to_string().into_bytes());
        let ack = |i: usize| CommittedAck::At { at: Seq(i as u64) };

        for i in 0..cap {
            memo.put(s, id(i), OpKind::Delete, ack(i));
        }
        // A memo filled exactly to capacity has dropped nothing — and asking
        // for the oldest entry is what makes it the newest.
        assert!(
            memo.get(s, &id(0), OpKind::Delete).is_some(),
            "a memo at capacity has evicted nothing yet"
        );
        // One entry past the bound: something must go.
        memo.put(s, id(cap), OpKind::Delete, ack(cap));
        assert!(
            memo.get(s, &id(0), OpKind::Delete).is_some(),
            "the entry just replayed is the most recently used, not the victim"
        );
        assert!(
            memo.get(s, &id(1), OpKind::Delete).is_none(),
            "the least recently used entry is what the bound evicts"
        );
        assert!(
            memo.get(s, &id(cap), OpKind::Delete).is_some(),
            "the entry that overflowed the bound is memoized"
        );
    }
}
