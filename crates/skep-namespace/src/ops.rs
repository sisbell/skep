//! §B Entity operations — *transact-wrapped*: M3 drives the transaction
//! (called by M10). Each op opens ONE M2 `transact`, evaluates its race-prone
//! gates inside the closure against `stg.base().m3()` under the held locks
//! (§6/§8), mints off `stg.working().m3()`, stages its [`M3Rec`] deltas
//! lifted via the `W::Record: From<M3Rec>` bound, and returns
//! `(Address, Seq)` — the new address plus `transact`'s committed `last_seq`
//! (the linearization coordinate) — only after commit
//! (commit-before-acknowledge).

use std::sync::Arc;

use skep_address::{is_prefix, parent, validate, zeros, Address, Level, Tumbler};
use skep_kernel::{Kernel, Seq, TxnError, WorldState};

use crate::error::{DelegateError, NodeError, OpError};
use crate::state::{bootstrap_root, namespace, ns_lock_key};
use crate::{HasM3, M3Rec, M3State, PrincipalId};

/// M3's transact-driving op handle over M2 (§B): a thin wrapper holding the
/// shared kernel. The pure mints and queries live on [`M3State`] (reached
/// through [`HasM3`]); this type owns only the four entity operations M10
/// dispatches.
pub struct Namespace<W: WorldState> {
    kernel: Arc<Kernel<W>>,
}

impl<W: WorldState> Namespace<W> {
    /// Wrap the engine's kernel. (Construction is not itself an
    /// interface-listed item, but the declared handle — which "holds
    /// `Arc<Kernel<W>>`" — is unusable without one; this is the minimal
    /// constructor, nothing more.)
    pub fn new(kernel: Arc<Kernel<W>>) -> Namespace<W> {
        Namespace { kernel }
    }
}

impl<W: WorldState + HasM3> Namespace<W>
where
    W::Record: From<M3Rec>,
{
    /// Baptize a fresh empty document under `account` [ASN-0103; §7].
    ///
    /// Authorization is by EFFECTIVE owner ω, never bare containment (O5 —
    /// the ownership-divergence trap): `OpError::NotOwner` if ω(`account`)
    /// is absent or names another principal. The ω read is evaluated first,
    /// in-closure against `stg.base().m3()`; it is stale-safe (ω of an
    /// *existing* account is stable — §6/§8), so the held
    /// [`M3State::principals_lock_key`] is defensive, not load-bearing. With
    /// auth passed, the structural mint gate surfaces as `OpError::Mint`
    /// (`NotAnAccount` covers unregistered and non-account alike — P8).
    ///
    /// Registers d only — no M5 arrangement write (lazy — Conflicts §3). No
    /// idempotency key (identity is the address; a retried lost-ack yields a
    /// harmless orphan empty document — exactly-once is M10's). Returns the
    /// address and its commit `Seq` only after commit
    /// (commit-before-acknowledge).
    pub fn create_new_document(
        &self,
        caller: PrincipalId,
        account: &Address,
    ) -> Result<(Address, Seq), TxnError<OpError>> {
        let keys = [
            M3State::document_lock_key(account),
            M3State::principals_lock_key(),
        ];
        self.kernel.transact(&keys, |stg| {
            match stg.base().m3().effective_owner(account) {
                Some(p) if p.id == caller => {}
                _ => return Err(OpError::NotOwner),
            }
            let (addr, rec) = stg
                .working()
                .m3()
                .mint_document(account)
                .map_err(OpError::Mint)?;
            stg.push(rec.into());
            Ok(addr)
        })
    }

    /// Delegation [ASN-0042 O15/O17b/O17c; §6]: the O15 five-condition gate
    /// — with (iii) NARROWED to `zeros == 1` (account-tier only; Conflicts
    /// §7) — PLUS id-freshness PLUS P8 (parent registered — Conflicts §5)
    /// PLUS next-form; then baptizes the new account prefix AND registers
    /// the principal in ONE transaction (a two-phase baptize-then-register
    /// could half-fail).
    ///
    /// Pure pre-work runs first: the validate-lift (`NotValid`) and the
    /// HOISTED tier check (`NotAccountTier`) — hoisted because the lift
    /// alone does not make `namespace()`/lock-key construction safe (a
    /// 1-component node prefix is T4-valid but parentless — §6). Both
    /// pre-work failures reject via `TxnError::Rejected` with NO transaction
    /// opened. Every race-prone condition is then evaluated inside the
    /// closure against `stg.base().m3()` under the held namespace +
    /// global-principals locks; the id-freshness race is CROSS-namespace
    /// (same `new_id`, different `new_prefix`), which only the single global
    /// [`M3State::principals_lock_key`] serializes (§8).
    ///
    /// Rejection order is PINNED (§6): `NotValid` → `NotAccountTier` →
    /// `DelegatorUnknown` → `NotAncestor` → `NotAuthorized` → `NotTopDown`
    /// → `NotFresh` → `DuplicateId` → `ParentNotRegistered` →
    /// `NotNextForm`; a multiply-defective input earns the FIRST applicable
    /// rejection. Obtain the required next-form `new_prefix` from
    /// [`M3State::next_account_prefix`] instead of guess-and-retry.
    pub fn delegate(
        &self,
        delegator: PrincipalId,
        new_prefix: Tumbler,
        new_id: PrincipalId,
    ) -> Result<(Address, Seq), TxnError<DelegateError>> {
        // Pre-work (§6): validate-lift, then the hoisted tier check (iii) —
        // only after it are parent()/namespace() total on new_prefix.
        let np = validate(new_prefix).map_err(|_| TxnError::Rejected(DelegateError::NotValid))?;
        if zeros(np.tumbler()) != 1 {
            return Err(TxnError::Rejected(DelegateError::NotAccountTier));
        }
        // One NsKey serves the held lock, the next-form check, and the
        // staged Allocate — the same key by construction (§1/§6).
        let ns = namespace(np.tumbler());
        let keys = [ns_lock_key(&ns), M3State::principals_lock_key()];
        self.kernel.transact(&keys, move |stg| {
            let base = stg.base().m3();
            // Delegator resolution — (i)/(ii) need dp (the §5 scan).
            let dp = base
                .principal_prefix(delegator)
                .ok_or(DelegateError::DelegatorUnknown)?;
            // (i) ancestry: dp ≺ new_prefix, strict [monotone — pfx
            // immutable, O13].
            if !is_prefix(dp.tumbler(), np.tumbler()) || dp.tumbler() == np.tumbler() {
                return Err(DelegateError::NotAncestor);
            }
            // (ii) authorization: the delegator is ω(new_prefix)
            // [non-monotone → in-closure].
            if !matches!(base.effective_owner(&np), Some(p) if p.id == delegator) {
                return Err(DelegateError::NotAuthorized);
            }
            // (iv) top-down: no principal strictly under new_prefix — the T5
            // single probe [non-monotone].
            if base.has_principal_strictly_under(np.tumbler()) {
                return Err(DelegateError::NotTopDown);
            }
            // (v) freshness: unallocated (T4-validity was the pre-work lift)
            // [non-monotone].
            if base.is_allocated(&np) {
                return Err(DelegateError::NotFresh);
            }
            // id-freshness: one id ↦ at most one principal — the id-axis
            // mirror of O1b [non-monotone, cross-namespace — §8].
            if base.principal_by_id(new_id).is_some() {
                return Err(DelegateError::DuplicateId);
            }
            // P8: the new account's parent is a registered entity [monotone
            // — E append-only; grouped here to keep one evaluation site].
            let par =
                parent(&np).expect("zeros == 1 (hoisted tier check) ⇒ N·0·U ⇒ ≥ 3 components");
            if base.entity_level(&par).is_none() {
                return Err(DelegateError::ParentNotRegistered);
            }
            // next-form (O17c) — MANDATORY under the counter representation
            // (§6); a gate violation is a namespace that cannot produce a
            // next address at all.
            let next = base.next_in(&ns).map_err(|_| DelegateError::NotNextForm)?;
            if next != np {
                return Err(DelegateError::NotNextForm);
            }
            // Baptism + principal registration, one transaction (O17b).
            stg.push(
                M3Rec::Allocate {
                    addr: np.tumbler().clone(),
                }
                .into(),
            );
            stg.push(
                M3Rec::RegisterPrincipal {
                    prefix: np.tumbler().clone(),
                    id: new_id,
                }
                .into(),
            );
            Ok(np)
        })
    }

    /// Admit an externally-originated node [ASN-0047 NodeBaptism; §7]: the
    /// ADDRESS is chosen by provisioning, not minted here — the one
    /// validate-not-mint path (Conflicts §1). Guards, in order: T4-validity
    /// (`NotValid`), node level (`NotNode`), freshness (`NotFresh` — the
    /// held coarse [`M3State::node_lock_key`] makes a concurrent duplicate
    /// surface typed rather than silently coalesce, §7/§8), and bootstrap
    /// lineage `[1] ≼ addr` (`NotDescendantOfBootstrap`). Returns the node
    /// address and its commit `Seq`.
    pub fn register_node(&self, addr: Tumbler) -> Result<(Address, Seq), TxnError<NodeError>> {
        let keys = [M3State::node_lock_key()];
        self.kernel.transact(&keys, move |stg| {
            let ad = validate(addr).map_err(|_| NodeError::NotValid)?;
            if ad.level() != Level::Node {
                return Err(NodeError::NotNode);
            }
            if stg.base().m3().entity_level(&ad).is_some() {
                return Err(NodeError::NotFresh);
            }
            if !is_prefix(&bootstrap_root(), ad.tumbler()) {
                return Err(NodeError::NotDescendantOfBootstrap);
            }
            stg.push(
                M3Rec::RegisterNode {
                    addr: ad.tumbler().clone(),
                }
                .into(),
            );
            Ok(ad)
        })
    }

    /// Denial-as-fork, allocation half [ASN-0042 O10, account-tier case
    /// ONLY; §7]: a fresh document in the caller's OWN account. Resolves
    /// `pfx(caller)` off a snapshot — value-stable, since prefixes are
    /// immutable (O13) — so `fork` opens no transaction of its own; an
    /// unknown id returns `Err(TxnError::Rejected(OpError::NotOwner))`
    /// directly, opening NO transaction. Then reduces to
    /// [`Namespace::create_new_document`]`(caller, pfx(caller))`, whose
    /// ω-auth passes by construction (SelfOwnershipAtPrefix), and returns
    /// its `(Address, Seq)`.
    ///
    /// A node-tier caller is rejected with the typed
    /// `OpError::Mint(MintError::NotAnAccount)` — the node-tier O10 case is
    /// DROPPED, not relocated to `delegate` (Conflicts §6). M5 wires the
    /// shared content separately (mechanism/policy split).
    pub fn fork(&self, caller: PrincipalId) -> Result<(Address, Seq), TxnError<OpError>> {
        let snap = self.kernel.snapshot();
        let Some(pfx) = snap.world().m3().principal_prefix(caller) else {
            return Err(TxnError::Rejected(OpError::NotOwner));
        };
        self.create_new_document(caller, &pfx)
    }
}
