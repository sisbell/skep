//! The identity fold BESIDE the engine: the world-fact seam (`FoldCtx`
//! over the assembled `World`), the canonical rebuild at open, the live
//! fold the write path advances, the credential idempotency memo, and the
//! `key_set` read's identity half. It also holds the credential type table
//! ([`identity_types`], [`T_ENROLL`]/[`T_RETIRE`]/[`T_CLAIM`], [`addr_of`])
//! and [`published_unprojected`], which the fold and the policy both read.
//!
//! DERIVED STATE, and only that: the fold is rebuilt from the recovered
//! world at open and advanced from committed deposits at runtime — nothing
//! here writes a file. Fidelity rests on E4 (precheck ≡ fold): every
//! credential-typed link this daemon ever commits classified `Honored`
//! under the gate, so a rebuild that honors exactly the honorable set in a
//! canonical order reproduces the live fold for every journal this daemon
//! (or any RES-27-conforming daemon) wrote. A journal written OUTSIDE the
//! gates rebuilds under the canonical order, which can diverge from that
//! journal's own live-fold history — the divergence the spec's World-seated
//! slice exists to remove, recorded in the build report and riding to the
//! engine round.

use std::collections::HashMap;
use std::sync::LazyLock;

use skep_address::{document_of, validate, Address, Nat, Span, Tumbler};
use skep_content::HasContent;
use skep_febe::{ReqId, SessionId};
use skep_identity::{
    FoldCtx, IdentityState, KeySet, LinkDeposit, Owner, TypeAddrs, Values, Verdict,
};
use skep_links::{HasLinks, View};
use skep_namespace::{HasM3, BOOTSTRAP_PRINCIPAL};

use super::LockWrite;
use crate::World;

// ── the world-fact seam ──────────────────────────────────────────────────

/// The three credential type addresses — AUTH-7.1 horn B's allocation,
/// recorded for the commons-seeding table (see the build report): subspace
/// 3 of the ghost document `1.1.0.1.0.1`, ordinals 1–3 in the order
/// enroll · retire · claim.
///
/// Why subspace 3 discharges AUTH-3.70's unreachability obligation with no
/// store edit: content V-spec RESOLUTION only ever yields I-spans in the
/// CONTENT subspace (subspace 1) of real documents — M3's content mints are
/// the resolution's whole codomain — and no M3 door mints into any
/// document's subspace 3 at all, so these names are never allocated and no
/// resolved span can equal their subtree spans. `deposits_credential_link`
/// therefore answers false for every `Resolve` type slot without resolving
/// anything, which is exactly AUTH-2.61's lock-free classifier.
pub(super) const T_ENROLL: [u32; 9] = [1, 1, 0, 1, 0, 1, 0, 3, 1];
pub(super) const T_RETIRE: [u32; 9] = [1, 1, 0, 1, 0, 1, 0, 3, 2];
pub(super) const T_CLAIM: [u32; 9] = [1, 1, 0, 1, 0, 1, 0, 3, 3];

pub(super) fn addr_of(comps: &[u32]) -> Address {
    let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c)))
        .expect("the credential type components are nonempty");
    validate(t).expect("the credential type addresses are T4-valid by construction")
}

/// The ONE `TypeAddrs` (`IDENTITY_TYPES`, AUTH-2.79) — an I2 frozen
/// constant; every classifier and the fold read this instance.
pub(crate) fn identity_types() -> &'static TypeAddrs {
    static TYPES: LazyLock<TypeAddrs> = LazyLock::new(|| {
        TypeAddrs::new(addr_of(&T_ENROLL), addr_of(&T_RETIRE), addr_of(&T_CLAIM))
    });
    &TYPES
}

/// The engine's publication read on ONE address, unprojected: `a ∉
/// exception_set` and nothing else (PUB-7.5) — the AUTH fold's read
/// (AUTH-2.34), reached through [`super::fold::WorldCtx`]'s `is_published`.
/// `crate::auth::policy::published` is this after PUB-2.15's version-member projection, so the
/// two share their membership lookup and differ by exactly that step.
pub(super) fn published_unprojected(world: &World, a: &Address) -> bool {
    world.published(a)
}

/// The fold's four facts, answered off one `World` snapshot (AUTH-2.31):
/// `value_at` from M4's permascroll (I-bytes are immutable, so a head read
/// equals the deposit-commit read for every honored deposit), ω and
/// account-hood from M3, and publication from the engine's exception set —
/// the daemon's ONE publication SET (owner ruling D1, 2026-09-05; PUB-7.5),
/// which is M3's per-document bit indexed for a membership miss. The two
/// readings OF that set — this one and the publish-class gate's — differ by
/// PUB-2.15's projection alone, which `is_published` states below.
pub(crate) struct WorldCtx<'a>(pub &'a World);

impl Values for WorldCtx<'_> {
    fn value_at(&self, at: &Tumbler) -> Option<&[u8]> {
        // M5's write gate refuses empty content values, so AUTH-1.22's
        // ≥ 1-byte obligation is discharged upstream.
        self.0.content().value_at(at).map(|v| v.as_bytes())
    }
}

impl FoldCtx for WorldCtx<'_> {
    fn owner_of(&self, a: &Address) -> Option<Owner> {
        let m3 = self.0.m3();
        let prefix = m3.effective_owner_prefix(a)?.clone();
        Some(Owner {
            prefix,
            is_bootstrap: m3.is_effective_owner(BOOTSTRAP_PRINCIPAL, a),
        })
    }

    fn is_account(&self, a: &Address) -> bool {
        self.0.m3().is_registered_account(a)
    }

    /// AUTH-2.34, answered as owner ruling D1 states it: `doc ∉
    /// exception_set` and nothing else — the engine's derived membership
    /// index over M3's publication bit (PUB-7.5), read through
    /// [`published_unprojected`]; on a reconstruction the same
    /// call answers off the reconstructed world's own set (PUB-7.12), which
    /// `Engine::world_at` seeds before it replays.
    ///
    /// The RES-26 publish-class gate's read (`crate::auth::policy`'s `published`)
    /// is this membership lookup AFTER PUB-2.15's projection of a version
    /// member to its DOCUMENT, so the two share the lookup and differ by
    /// exactly that step. Where a credential home is a version member — the
    /// home pin fires later, in the per-kind arm, so this read sees one — the
    /// fold answers the MEMBER's own bit and the gate would answer its
    /// document's: on PUB-2.7's private-member cell (a member minted
    /// `Some(false)` under a published document, admitted until the routed
    /// write-path item lands, PUB-8.2) this answers `unpublished` where the
    /// projection would fall through to the home pin's `not_doc_one`. Both
    /// refuse, permanently, so the divergence is a token and not an admission;
    /// whether the fold should take the projection too is the spec's (see the
    /// build report).
    ///
    /// The document's BIRTH state, constant over every record's life: the
    /// bit is stamped at the mint that allocates the address and no op moves
    /// it afterwards — the wire's `publish` MINTS the chain's next member,
    /// published-born (PUB-2.5), rather than flipping any existing
    /// document's — and a link deposit allocates no document at all
    /// (PUB-1.9), so the pre-commit gate and the post-commit fold read one
    /// answer. The cell this moved (D1,
    /// `conformance/adjudication/decisions.md`): a credential deposited in a
    /// DRAFT-homed document now answers `unpublished` — AUTH-2.66 item 3 —
    /// where the constant-true v1 wiring let it fall through to the home
    /// pin's `not_doc_one`.
    ///
    /// The fold hands this the home `document_of` derived — a document
    /// address, a version member's own where the home is a version — and
    /// asks nothing of registration: an unregistered home has no ω and so
    /// answers `MalformedShape` at item 2, ahead of this read (PUB-6.37's
    /// registration-first discipline, in the fold's own order).
    fn is_published(&self, doc: &Address) -> bool {
        published_unprojected(self.0, doc)
    }
}

// ── the canonical rebuild ────────────────────────────────────────────────

/// One credential-shaped link lifted out of the store, spans owned.
struct Candidate {
    home: Address,
    from: Vec<Span>,
    to: Vec<Span>,
    ty: Vec<Span>,
    /// The claim kind folds after the non-claim deposits of its pass — the
    /// one ordering the address walk cannot supply (a pre-claim-committed
    /// own-space genesis may sit at a HIGHER address than the claim).
    is_claim: bool,
}

impl Candidate {
    fn deposit(&self) -> LinkDeposit<'_> {
        LinkDeposit { home: &self.home, from: &self.from, to: &self.to, ty: &self.ty }
    }
}

/// Rebuild the identity state from one world: fold every credential-shaped
/// link (audit view — a nullified deposit still counts, AUTH-2.78) to a
/// fixpoint, each pass stepping the still-pending deposits in address
/// order with claims last. Deterministic — a pure function of the world —
/// and equal to the live fold for every gate-written journal (module doc).
///
/// COST: one pass over EVERY link in `world` — M7's `match_links` with no
/// constraint is the whole audit slice — to lift the credential-shaped
/// ones, then a fixpoint over those, each pass re-stepping the
/// still-pending set, so `d` deposits that honor one per pass cost O(d²)
/// `step` calls. Paid at every [`crate::Daemon::open`], and at every
/// historical `key_set` read, which reconstructs a world and rebuilds over
/// it under one reconstruction permit.
///
/// The fixpoint carries a multiplier the shape above does not show: each
/// `step` re-reads and re-parses its deposit's record (bounded by
/// [`skep_identity::MAX_RECORD_BYTES`]), so the O(d²) above is O(d²) record
/// parses. The lift carries none: `kind_of` reads each link's STORED type
/// slot in place and decides its arity in at most two steps of the walk, so
/// the first pass is O(links) — at most three span comparisons each —
/// whatever [`skep_links::MAX_SLOT_SPANS`] admits, and only a
/// credential-shaped link's three slots are copied, into the `Candidate` its
/// borrowed `LinkDeposit` is built from.
pub(crate) fn canonical_identity(world: &World) -> IdentityState {
    let links = world.links();
    let types = identity_types();
    let mut pending: Vec<Candidate> = links
        .match_links(&[], View::Audit)
        .iter()
        .filter_map(|a| {
            let link = links.readlink(a)?;
            let kind = types.kind_of(link.type_slot())?;
            Some(Candidate {
                home: document_of(a)?,
                from: link.from_slot().spans().cloned().collect(),
                to: link.to_slot().spans().cloned().collect(),
                ty: link.type_slot().spans().cloned().collect(),
                is_claim: matches!(kind, skep_identity::CredentialKind::Claim),
            })
        })
        .collect();
    // Claims to the back of each pass, address order otherwise (the sort is
    // stable and match_links already walked in address order).
    pending.sort_by_key(|c| c.is_claim);
    let ctx = WorldCtx(world);
    let mut state = IdentityState::genesis();
    loop {
        let mut honored_this_pass = false;
        let mut still_pending = Vec::with_capacity(pending.len());
        for cand in pending {
            let (next, verdict) = state.step(types, &ctx, &cand.deposit());
            match verdict {
                Verdict::Honored(_) => {
                    state = next;
                    honored_this_pass = true;
                }
                // Inert now may honor after a later deposit lands (a
                // holder act ahead of its delegator-homed genesis).
                _ => still_pending.push(cand),
            }
        }
        pending = still_pending;
        if !honored_this_pass || pending.is_empty() {
            return state;
        }
    }
}

// ── the live fold ────────────────────────────────────────────────────────

/// The daemon's live identity state: seeded from the recovered world at
/// open, advanced under `credential_lock.write()` from every committed
/// credential deposit. Readers clone the state (im structures — root
/// clones).
pub(crate) struct IdentityFold {
    state: parking_lot::Mutex<IdentityState>,
}

impl IdentityFold {
    pub fn seeded(state: IdentityState) -> IdentityFold {
        IdentityFold { state: parking_lot::Mutex::new(state) }
    }

    /// The current state, by value — the head every lock-free reader
    /// resolves against (a read that resolved before a retirement reads
    /// pre-retirement state, AUTH-3.36).
    pub fn snapshot(&self) -> IdentityState {
        self.state.lock().clone()
    }

    /// Advance from one COMMITTED deposit — the credential path's, under
    /// the write guard it names in its arguments (AUTH-3.3): step the fold
    /// with the post-commit world as ctx. Returns whether this step flipped
    /// the board claimed — the claim-flip tail's trigger (AUTH-3.43).
    ///
    /// PRECONDITION: `dep` was committed by this write and classified
    /// `Honored` under the gate (E4), and `world_post` is the post-commit
    /// snapshot. The assert is what makes that premise loud; in release a
    /// non-`Honored` verdict leaves the fold unchanged —
    /// `IdentityState::step` returns its input state — and answers `false`,
    /// so the failure is closed rather than silent-and-wrong.
    ///
    /// The gate's verdict and this one are verdicts about two worlds — the
    /// gate read the PRE-commit snapshot — and they agree, which is what
    /// makes the assert checkable rather than a second, unrelated claim.
    /// Under the serialization lock the post-commit world differs from the
    /// one the gate read by this write's own records and — where this commit
    /// gave the head writer its turn
    /// ([`crate::write_path::WritePath::commit_under`]) — by that writer's:
    /// the system account's staging-draft mint, its insert, and the publish
    /// into `H`. Classify reads none of either: the record bytes at
    /// `from` are a prior write's atom, `owner_of`/`is_account` of the home
    /// read M3's principals and accounts, which neither a link deposit nor a
    /// document or member mint moves, and publication is the home's birth
    /// state, which neither moves (PUB-1.9). So a firing assert names a
    /// broken E4 and not a classification that shifted underneath it.
    ///
    /// The bool is a COMMAND's answer, and the licensed kind: the flip is a
    /// property of the TRANSITION rather than of the resulting state, so no
    /// query can recover it — a caller would have to clone the fold either
    /// side of the step, under the same guard, to learn what this returns
    /// for nothing.
    pub fn step_committed(
        &self,
        _lock: &LockWrite<'_>,
        world_post: &World,
        dep: &LinkDeposit<'_>,
    ) -> bool {
        let mut state = self.state.lock();
        let was_claimed = state.claimant().is_some();
        let (next, verdict) = state.step(identity_types(), &WorldCtx(world_post), dep);
        debug_assert!(
            matches!(verdict, Verdict::Honored(_)),
            "a committed credential deposit must fold honored (E4): {verdict:?}"
        );
        *state = next;
        !was_claimed && state.claimant().is_some()
    }
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
    /// reached through [`super::AuthState::commit_tail`], which performs
    /// this and the fold step as one operation.
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
/// both `/op` (head, live fold) and `/op-at` (reconstructed world,
/// canonical rebuild) call, so the two routes cannot diverge on it. The
/// rendering is [`crate::codec::key_set_reply`]'s, where every wire shape
/// this crate emits is rendered.
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
    use super::*;

    /// The class types a `deposit` field can usefully carry are SPELLED
    /// TWICE — M5's set, which its insert door tests a declaration against
    /// and which sits below this crate, and the daemon's own credential
    /// constants, which the fold classifies the pair's `make_link` by — and
    /// the two are pinned EQUAL here, member for member in the set's order,
    /// ENROLL then RETIRE (PUB-2.11, PUB-2.63; RES-249, RES-261). This is
    /// the one place both spellings are in reach: the constants are this
    /// crate's own and no integration suite can name them, and the codec's
    /// `deposit` parse is where a declared type enters the daemon. If this
    /// fails, an enrollment a client declares as the fold will classify it
    /// is refused `published_target` at the store — or admitted there and
    /// typed as nothing the fold honors.
    #[test]
    fn the_deposit_class_types_are_the_daemons_enroll_and_retire_constants() {
        let spelled: Vec<Vec<Nat>> = skep_arrangement::deposit_class_types()
            .iter()
            .map(|ty| ty.tumbler().iter().cloned().collect())
            .collect();
        assert_eq!(spelled, [T_ENROLL.map(Nat::from).to_vec(), T_RETIRE.map(Nat::from).to_vec()]);
    }
}
