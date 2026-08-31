//! The identity fold BESIDE the engine: the world-fact seam (`FoldCtx`
//! over the assembled `World`), the canonical rebuild at open, the live
//! fold the write path advances, the credential idempotency memo, and the
//! `key_set` read's identity half.
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

use skep_address::{document_of, Address, Level, Span, Tumbler};
use skep_content::HasContent;
use skep_febe::{ReqId, SessionId};
use skep_identity::{FoldCtx, IdentityState, KeySet, LinkDeposit, Owner, Values, Verdict};
use skep_links::{HasLinks, View};
use skep_namespace::{HasM3, BOOTSTRAP_PRINCIPAL};

use super::policy::identity_types;
use crate::World;

// ── the world-fact seam ──────────────────────────────────────────────────

/// The fold's four facts, answered off one `World` snapshot (AUTH-2.31):
/// `value_at` from M4's permascroll (I-bytes are immutable, so a head read
/// equals the deposit-commit read for every honored deposit), ω and
/// account-hood from M3, and v1's constant-true publication (AUTH-2.117 —
/// no draft substrate exists in this workspace; the precheck's
/// guest-publication read degenerates to this constant, see the report).
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
        let id = m3.effective_owner(a)?;
        let prefix = m3.principal_prefix(id)?.clone();
        Some(Owner { prefix, is_bootstrap: id == BOOTSTRAP_PRINCIPAL })
    }

    fn is_account(&self, a: &Address) -> bool {
        self.0.m3().entity_level(a) == Some(Level::Account)
    }

    /// The daemon's OTHER publication read is
    /// [`super::policy::is_published_v1`], which computes v1's real answer
    /// (a document is published iff it IS its account's doc 1) for the
    /// RES-26 publish gate. The two are one design decision under two
    /// rules, and they agree on every credential home — which the home pin
    /// confines to doc 1, the argument written there. A draft substrate
    /// moves both.
    fn is_published(&self, _doc: &Address) -> bool {
        true
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
pub(crate) fn canonical_identity(world: &World) -> IdentityState {
    let links = world.links();
    let types = identity_types();
    let mut pending: Vec<Candidate> = links
        .match_links(&[], View::Audit)
        .iter()
        .filter_map(|a| {
            let link = links.readlink(a)?;
            let ty: Vec<Span> = link.type_slot().spans().cloned().collect();
            let kind = types.kind_of(&ty)?;
            Some(Candidate {
                home: document_of(a)?,
                from: link.from_slot().spans().cloned().collect(),
                to: link.to_slot().spans().cloned().collect(),
                ty,
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
        let mut still = Vec::with_capacity(pending.len());
        for cand in pending {
            let (next, verdict) = state.step(types, &ctx, &cand.deposit());
            match verdict {
                Verdict::Honored(_) => {
                    state = next;
                    honored_this_pass = true;
                }
                // Inert now may honor after a later deposit lands (a
                // holder act ahead of its delegator-homed genesis).
                _ => still.push(cand),
            }
        }
        pending = still;
        if !honored_this_pass || pending.is_empty() {
            return state;
        }
    }
}

// ── the live fold ────────────────────────────────────────────────────────

/// The daemon's live identity state: seeded from the recovered world at
/// open, advanced under `gate.write()` from every committed credential
/// deposit. Readers clone the state (im structures — root clones).
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

    /// Advance from one COMMITTED deposit (the credential path's, under
    /// `gate.write()`): step the fold with the post-commit world as ctx.
    /// Returns whether this step flipped the board claimed — the claim-flip
    /// tail's trigger (AUTH-3.43).
    pub fn step_committed(&self, world_post: &World, dep: &LinkDeposit<'_>) -> bool {
        let mut g = self.state.lock();
        let was_claimed = g.claimant().is_some();
        let (next, verdict) = g.step(identity_types(), &WorldCtx(world_post), dep);
        debug_assert!(
            matches!(verdict, Verdict::Honored(_)),
            "a committed credential deposit must fold honored (E4): {verdict:?}"
        );
        *g = next;
        !was_claimed && g.claimant().is_some()
    }
}

// ── the credential idempotency memo (AUTH-3.40–3.42, AUTH-6.33–6.34) ─────

/// Per-`(SessionId, ReqId)` memo of marshaled credential acks — skepd's
/// own, because M10's memo exposes no `recall` accessor in this workspace
/// (a report finding; the semantics are the pinned ones): the ORIGINAL
/// ack, byte-identical, no execution; KIND-BLIND on a hit; uptime-scoped;
/// consulted inside `gate.write()` before the precheck; purged with its
/// session. Stores marshaled bytes at execute time (AUTH-7.20's first
/// horn).
pub(crate) struct CredMemo {
    map: parking_lot::Mutex<HashMap<(SessionId, ReqId), Vec<u8>>>,
}

impl CredMemo {
    pub fn new() -> CredMemo {
        CredMemo { map: parking_lot::Mutex::new(HashMap::new()) }
    }

    pub fn recall(&self, sid: SessionId, id: &ReqId) -> Option<Vec<u8>> {
        self.map.lock().get(&(sid, id.clone())).cloned()
    }

    pub fn store(&self, sid: SessionId, id: &ReqId, ack: Vec<u8>) {
        self.map.lock().insert((sid, id.clone()), ack);
    }

    /// A closed session takes its memo entries with it — the same
    /// obligation M10's own `close_session` discharges for its cache.
    pub fn purge(&self, sid: SessionId) {
        self.map.lock().retain(|(s, _), _| *s != sid);
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
    (world.m3().entity_level(account) == Some(Level::Account))
        .then(|| identity.key_set(account))
}

