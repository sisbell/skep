//! The daemon's READERS of the World's identity slice, and the credential
//! idempotency memo beside them. The identity fold itself lives in the
//! engine since the World-seated slice landed (AUTH-2.79–2.88): `World`
//! carries the `IdentityState`, `World::apply` steps it at every credential
//! deposit's commit (AUTH-2.80) and every checkpoint carries it, so the
//! daemon REBUILDS NOTHING at open and advances nothing at runtime — it reads
//! the slice off whichever World snapshot it holds, through
//! [`skep_identity::HasIdentity`], and one snapshot carries the world and its
//! table together. The credential type table the daemon classifies by is the
//! engine's too ([`skep_engine::types::IDENTITY_TYPES`] and its three pins),
//! one instance for the fold hook and every classifier here.
//!
//! What this module keeps is the daemon's own: [`key_set_of`], the `key_set`
//! read's identity half with its one account-hood test, shared by `/op` and
//! `/op-at`; [`published_unprojected`], the publication read the write
//! path's gate and the fold share their membership lookup through; and
//! [`CredMemo`], the credential path's idempotency memo, which is process
//! memory and never world state.

use std::collections::HashMap;

use skep_address::Address;
use skep_febe::{ReqId, SessionId};
use skep_identity::{IdentityState, KeySet};
use skep_namespace::HasM3;

use super::LockWrite;
use crate::World;

/// A T4-valid address from its components — the policy suites' one spelling
/// of a test address.
#[cfg(test)]
pub(super) fn addr_of(comps: &[u32]) -> Address {
    use skep_address::{validate, Nat, Tumbler};
    let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty");
    validate(t).expect("test addresses are T4-valid by construction")
}

/// The engine's publication read on ONE address, unprojected: `a ∉
/// exception_set` and nothing else (PUB-7.5) — the AUTH fold's read
/// (AUTH-2.34), which the engine's `FoldCtx for World` answers off the same
/// set. `policy/plain.rs`'s `published` is this after PUB-2.15's
/// version-member projection, so the two share their membership lookup and
/// differ by exactly that step. The daemon's ONE publication SET (owner
/// ruling D1, 2026-09-05; PUB-7.5), which is M3's per-document bit indexed
/// for a membership miss.
pub(super) fn published_unprojected(world: &World, a: &Address) -> bool {
    world.published(a)
}

// ── the credential idempotency memo (AUTH-3.40–3.42, AUTH-6.33–6.34) ─────

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

// ── the key_set read's identity half (AUTH-6.18–6.20) ────────────────────

/// The key set one `(world, identity)` pair holds for an address, or
/// `None` when the address is not an account — the ONE account-hood test
/// both `/op` (the head snapshot) and `/op-at` (the reconstructed world)
/// call, so the two routes cannot diverge on it. Both hand the slice the
/// SAME world carries, so the account-hood and the table stand on one
/// committed state (AUTH-6.20: "`/op-at` on the reconstructed World, the
/// slice riding in it"). The rendering is [`crate::codec::key_set_reply`]'s,
/// where every wire shape this crate emits is rendered.
pub(crate) fn key_set_of<'a>(
    world: &World,
    identity: &'a IdentityState,
    account: &Address,
) -> Option<&'a KeySet> {
    world
        .m3()
        .is_registered_account(account)
        .then(|| identity.key_set(account))
}

#[cfg(test)]
mod tests {
    use skep_address::{subtree_of, Nat};
    use skep_engine::types::{t_claim, t_enroll, t_retire, IDENTITY_TYPES};
    use skep_identity::CredentialKind;

    use super::*;

    /// The five reserved subtree spans overlap nothing the credential types
    /// name: the identity types live in subspace 3 while the shipped classes
    /// sit at content positions 1..=5 — pinned so a change to either
    /// allocation fails here rather than in a fold. The table is the
    /// engine's one instance, which the fold hook and this daemon's
    /// classifiers all read.
    #[test]
    fn identity_types_are_distinct_and_recognized() {
        let enroll_span = subtree_of(t_enroll().tumbler());
        assert_eq!(IDENTITY_TYPES.kind_of(&[enroll_span]), Some(CredentialKind::Enroll));
        let retire_span = subtree_of(t_retire().tumbler());
        assert_eq!(IDENTITY_TYPES.kind_of(&[retire_span]), Some(CredentialKind::Retire));
        let claim_span = subtree_of(t_claim().tumbler());
        assert_eq!(IDENTITY_TYPES.kind_of(&[claim_span]), Some(CredentialKind::Claim));
        // A shipped reserved type (ghost position 1, the content subspace)
        // is NOT a credential type.
        let shipped_span = subtree_of(addr_of(&[1, 1, 0, 1, 0, 1, 0, 1, 1]).tumbler());
        assert_eq!(IDENTITY_TYPES.kind_of(&[shipped_span]), None);
    }

    /// AUTH-3.70's conformance expression in miniature: a content-I-span
    /// type slot answers no credential kind — a resolved span's start is a
    /// mintable content position, never a subspace-3 name.
    #[test]
    fn a_content_span_ty_is_never_credential() {
        // Content position 1 of some ordinary doc: <doc>.0.1.1.
        let content = subtree_of(addr_of(&[1, 0, 1, 0, 1, 0, 1, 1]).tumbler());
        assert_eq!(IDENTITY_TYPES.kind_of(&[content]), None);
    }

    /// The class types a `deposit` field can usefully carry are SPELLED
    /// TWICE — M5's set, which its insert door tests a declaration against
    /// and which sits below this crate and the engine, and the engine's
    /// credential pins, which the fold hook classifies the pair's
    /// `make_link` by — and the two are pinned EQUAL here, member for member
    /// in the set's order, ENROLL then RETIRE (PUB-2.11, PUB-2.63; RES-249,
    /// RES-261), the set's two further members being the registry's binding
    /// and endpoint, the engine ledger's rows, which the registry sequence
    /// classifies by (REG-1.37 as the record grade for registry records
    /// re-reads it). The engine's own ledger holds the same equality; this
    /// is the daemon's reading of it, at the door where a declared type
    /// enters: if this fails, an enrollment a client declares as the fold
    /// will classify it is refused `published_target` at the store — or
    /// admitted there and typed as nothing the fold honors.
    #[test]
    fn the_deposit_class_types_are_the_engines_enroll_and_retire_pins() {
        let spelled: Vec<Vec<Nat>> = skep_arrangement::deposit_class_types()
            .iter()
            .map(|ty| ty.tumbler().iter().cloned().collect())
            .collect();
        let row = |a: &Address| -> Vec<Nat> { a.tumbler().iter().cloned().collect() };
        assert_eq!(
            spelled,
            [
                row(t_enroll()),
                row(t_retire()),
                row(skep_engine::types::t_binding()),
                row(skep_engine::types::t_endpoint()),
            ]
        );
        assert_eq!(t_enroll().tumbler().to_string(), "1.1.0.1.0.1.0.3.1");
        assert_eq!(t_retire().tumbler().to_string(), "1.1.0.1.0.1.0.3.2");
        assert_eq!(t_claim().tumbler().to_string(), "1.1.0.1.0.1.0.3.3");
    }
}
