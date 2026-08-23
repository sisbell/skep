//! §B Entity operations — *transact-wrapped*: M3 drives the transaction
//! (called by M10). Each op opens ONE M2 `transact`, evaluates its race-prone
//! gates inside the closure against `stg.base().m3()` under the held locks
//! (§6/§8), mints off `stg.working().m3()`, stages its [`M3Rec`] deltas
//! lifted via the `W::Record: From<M3Rec>` bound, and returns
//! `(Address, Seq)` — the new address plus `transact`'s committed `last_seq`
//! (the linearization coordinate) — only after commit
//! (commit-before-acknowledge).

use skep_address::{parent, validate, Address, Level, Tumbler};
use skep_kernel::{Kernel, Seq, TxnError, WorldState};

use crate::error::{CreateDocumentError, DelegateError, NodeError};
use crate::state::{bootstrap_root, namespace_of, ns_lock_key};
use crate::{prefix_contains, HasM3, M3Rec, M3State, PrincipalId, MAX_NODE_COMPONENTS};

/// M3's transact-driving op handle over M2 (§B): a thin borrow of the
/// engine's kernel. The pure mints and queries live on [`M3State`] (reached
/// through [`HasM3`]); this type owns only the four entity operations M10
/// dispatches.
pub struct Namespace<'k, W: WorldState> {
    kernel: &'k Kernel<W>,
}

impl<'k, W: WorldState> Namespace<'k, W> {
    /// Borrow the engine's kernel — the handle holds nothing else, so this is
    /// the whole of its construction.
    pub fn new(kernel: &'k Kernel<W>) -> Namespace<'k, W> {
        Namespace { kernel }
    }
}

impl<W: WorldState + HasM3> Namespace<'_, W>
where
    W::Record: From<M3Rec>,
{
    /// Baptize a fresh empty document under `account` [ASN-0103; §7].
    ///
    /// Authorization is by EFFECTIVE owner ω, never bare containment (O5 —
    /// the ownership-divergence trap): `CreateDocumentError::NotOwner` if
    /// ω(`account`) is absent or names another principal. The ω read is
    /// evaluated first, in-closure against `stg.base().m3()`; it is
    /// stale-safe (ω of an *existing* account is stable — §6/§8), so the held
    /// [`M3State::principals_lock_key`] is defensive, not load-bearing. With
    /// auth passed, the structural mint gate surfaces as
    /// `CreateDocumentError::Mint` (`NotAnAccount` covers unregistered and
    /// non-account alike — P8).
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
    ) -> Result<(Address, Seq), TxnError<CreateDocumentError>> {
        let keys = [
            M3State::document_lock_key(account),
            M3State::principals_lock_key(),
        ];
        self.kernel.transact(&keys, |stg| {
            if !stg.base().m3().is_effective_owner(caller, account) {
                return Err(CreateDocumentError::NotOwner);
            }
            let (addr, rec) = stg.working().m3().mint_document(account)?;
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
    /// alone does not make `namespace_of`/lock-key construction safe (a
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
        // only after it are parent()/namespace_of() total on new_prefix.
        let new_prefix =
            validate(new_prefix).map_err(|_| TxnError::Rejected(DelegateError::NotValid))?;
        if new_prefix.level() != Level::Account {
            return Err(TxnError::Rejected(DelegateError::NotAccountTier));
        }
        // One NsKey serves the held lock, the next-form check, and the
        // staged Allocate — the same key by construction (§1/§6).
        let ns = namespace_of(&new_prefix)
            .expect("account tier (hoisted tier check) ⇒ N·0·U ⇒ ≥ 3 components");
        let keys = [ns_lock_key(&ns), M3State::principals_lock_key()];
        self.kernel.transact(&keys, move |stg| {
            let base = stg.base().m3();
            // Delegator resolution: an unknown id rejects here, and (i) needs
            // the prefix itself, which Π answers by id only through the §5
            // scan.
            let delegator_prefix = base
                .principal_prefix(delegator)
                .ok_or(DelegateError::DelegatorUnknown)?;
            // (i) ancestry: the delegator's prefix ≺ new_prefix, strict
            // [monotone — pfx immutable, O13].
            if !prefix_contains(delegator_prefix, &new_prefix) || *delegator_prefix == new_prefix {
                return Err(DelegateError::NotAncestor);
            }
            // (ii) authorization: the delegator is ω(new_prefix)
            // [non-monotone → in-closure].
            if !base.is_effective_owner(delegator, &new_prefix) {
                return Err(DelegateError::NotAuthorized);
            }
            // (iv) top-down: no principal strictly under new_prefix — the T5
            // single probe [non-monotone].
            if base.has_principal_strictly_under(&new_prefix) {
                return Err(DelegateError::NotTopDown);
            }
            // (v) freshness: unallocated (T4-validity was the pre-work lift)
            // [non-monotone].
            if base.is_allocated(&new_prefix) {
                return Err(DelegateError::NotFresh);
            }
            // id-freshness: one id ↦ at most one principal — the id-axis
            // mirror of O1b [non-monotone, cross-namespace — §8].
            if base.principal_prefix(new_id).is_some() {
                return Err(DelegateError::DuplicateId);
            }
            // P8: the new account's parent is a registered entity [monotone
            // — E append-only; grouped here to keep one evaluation site].
            let par = parent(&new_prefix)
                .expect("account tier (hoisted tier check) ⇒ N·0·U ⇒ ≥ 3 components");
            if base.entity_level(&par).is_none() {
                return Err(DelegateError::ParentNotRegistered);
            }
            // next-form (O17c) — MANDATORY under the counter representation
            // (§6).
            let next = base.next_in(&ns).expect(
                "account tier (hoisted tier check) ⇒ the anchor is node- or account-level ⇒ next_in's precondition holds",
            );
            if next != new_prefix {
                return Err(DelegateError::NotNextForm);
            }
            // Baptism + principal registration, one transaction (O17b).
            stg.push(M3Rec::Allocate { addr: new_prefix.clone() }.into());
            stg.push(
                M3Rec::RegisterPrincipal {
                    prefix: new_prefix.clone(),
                    id: new_id,
                }
                .into(),
            );
            Ok(new_prefix)
        })
    }

    /// Admit an externally-originated node [ASN-0047 NodeBaptism; §7]: the
    /// ADDRESS is chosen by provisioning, not minted here — the one
    /// validate-not-mint path (Conflicts §1). Guards, in order: T4-validity
    /// (`NotValid`), node level (`NotNode`), depth
    /// ([`MAX_NODE_COMPONENTS`] — `TooDeep`), freshness (`NotFresh` — the
    /// held coarse [`M3State::node_lock_key`] makes a concurrent duplicate
    /// surface typed rather than silently coalesce, §7/§8), and bootstrap
    /// lineage `[1] ≼ addr` (`NotDescendantOfBootstrap`). Returns the node
    /// address and its commit `Seq`.
    ///
    /// The first three guards are pure pre-work — validity, level and depth
    /// are decidable from the address alone — so a malformed or oversized
    /// input rejects via `TxnError::Rejected` with NO transaction opened;
    /// only the two state-reading guards run under the held lock.
    ///
    /// The depth guard is a resource refusal, not a shape one: this is the
    /// single path by which bytes a caller chose enter a permanent,
    /// uncompressed registry, and the op takes no `caller`, so ω cannot gate
    /// it here — the SIZE of an entry is what M3 can bound, and it does.
    /// How MANY admissions a session may make is the daemon's.
    pub fn register_node(&self, addr: Tumbler) -> Result<(Address, Seq), TxnError<NodeError>> {
        // Pre-work (§7): the state-free half of the guard order.
        let addr = validate(addr).map_err(|_| TxnError::Rejected(NodeError::NotValid))?;
        if addr.level() != Level::Node {
            return Err(TxnError::Rejected(NodeError::NotNode));
        }
        if addr.tumbler().len() > MAX_NODE_COMPONENTS {
            return Err(TxnError::Rejected(NodeError::TooDeep));
        }
        let keys = [M3State::node_lock_key()];
        self.kernel.transact(&keys, move |stg| {
            if stg.base().m3().entity_level(&addr).is_some() {
                return Err(NodeError::NotFresh);
            }
            if !prefix_contains(&bootstrap_root(), &addr) {
                return Err(NodeError::NotDescendantOfBootstrap);
            }
            stg.push(M3Rec::RegisterNode { addr: addr.clone() }.into());
            Ok(addr)
        })
    }

    /// Denial-as-fork, allocation half [ASN-0042 O10, account-tier case
    /// ONLY; §7]: a fresh document in the caller's OWN account. Resolves
    /// `pfx(caller)` off a snapshot — value-stable, since prefixes are
    /// immutable (O13) — so `fork` opens no transaction of its own; an
    /// unknown id returns
    /// `Err(TxnError::Rejected(CreateDocumentError::NotOwner))` directly,
    /// opening NO transaction. Then reduces to
    /// [`Namespace::create_new_document`]`(caller, pfx(caller))`, whose
    /// ω-auth passes by construction (SelfOwnershipAtPrefix), and returns
    /// its `(Address, Seq)`.
    ///
    /// A node-tier caller is rejected with the typed
    /// `CreateDocumentError::Mint(MintError::NotAnAccount)` — the node-tier
    /// O10 case is DROPPED, not relocated to `delegate` (Conflicts §6). M5
    /// wires the shared content separately (mechanism/policy split).
    pub fn fork(&self, caller: PrincipalId) -> Result<(Address, Seq), TxnError<CreateDocumentError>> {
        let snap = self.kernel.snapshot();
        let Some(pfx) = snap.world().m3().principal_prefix(caller) else {
            return Err(TxnError::Rejected(CreateDocumentError::NotOwner));
        };
        self.create_new_document(caller, pfx)
    }
}
