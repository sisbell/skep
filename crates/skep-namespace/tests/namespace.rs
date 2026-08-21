//! Integration tests for M3's public surface. Each test states a claim the
//! design/interface actually makes (§-references inline): what constructors
//! and gates admit and reject, which rejection wins on a multiply-defective
//! input (the pinned orders), that the journaled types survive a serde round
//! trip, and that each part of the interface does its ordinary job. The toy
//! `World`/`Rec` pair is the minimal engine assembly the composition
//! contract prescribes: `HasM3` read accessor, `From<M3Rec>` record lift,
//! `apply` dispatching into `M3State::apply_ns`.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Level, Nat, Tumbler};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelCfg, TxnError, WorldState,
};
use skep_namespace::{
    DelegateError, HasM3, M3Rec, M3State, MintError, Namespace, NodeError, OpError, Principal,
    PrincipalId, BOOTSTRAP_PRINCIPAL,
};
use tempfile::tempdir;

// ---- the minimal engine assembly (composition contract) ----

#[derive(Clone, Serialize, Deserialize)]
struct World {
    m3: M3State,
}

#[derive(Clone, Serialize, Deserialize)]
struct Rec(M3Rec);

impl From<M3Rec> for Rec {
    fn from(r: M3Rec) -> Rec {
        Rec(r)
    }
}

impl HasM3 for World {
    fn m3(&self) -> &M3State {
        &self.m3
    }
}

impl WorldState for World {
    type Record = Rec;
    fn apply(&self, r: &Rec) -> World {
        World {
            m3: self.m3.apply_ns(&r.0),
        }
    }
}

// ---- helpers ----

fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

fn a(comps: &[u32]) -> Address {
    validate(t(comps)).expect("test addresses are T4-valid")
}

fn alloc(comps: &[u32]) -> M3Rec {
    M3Rec::Allocate { addr: t(comps) }
}

fn genesis_world() -> World {
    World {
        m3: M3State::genesis(),
    }
}

fn mem_kernel(genesis: World) -> Arc<Kernel<World>> {
    let cfg = KernelCfg {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
    };
    Arc::new(Kernel::open(cfg, genesis).expect("in-memory open"))
}

fn cfg_fsync(dir: &Path) -> KernelCfg {
    KernelCfg {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 1,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
    }
}

/// Unwrap an op's typed rejection (`TxnError::Rejected(E)` — surfaced
/// verbatim, per M2's transact contract).
fn rejected<T: std::fmt::Debug, E: std::fmt::Debug>(r: Result<T, TxnError<E>>) -> E {
    match r {
        Err(TxnError::Rejected(e)) => e,
        other => panic!("expected TxnError::Rejected, got {other:?}"),
    }
}

/// Unwrap a pure mint's rejection (M3Rec carries no Debug, so no unwrap_err).
fn mint_err(r: Result<(Address, M3Rec), MintError>) -> MintError {
    match r {
        Err(e) => e,
        Ok((addr, _)) => panic!("expected a mint rejection, minted {addr:?}"),
    }
}

const ID1: PrincipalId = PrincipalId(1);
const ID2: PrincipalId = PrincipalId(2);

/// The standard fixture: genesis, then `delegate [1,0,1] → ID1`, then
/// `create_new_document` under it (⇒ doc `[1,0,1,0,1]`).
fn with_account_and_doc() -> (Arc<Kernel<World>>, Namespace<World>, Address, Address) {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(Arc::clone(&k));
    let (acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("bootstrap delegates the first account");
    let (doc, _) = ns
        .create_new_document(ID1, &acct)
        .expect("the delegate creates a document");
    (k, ns, acct, doc)
}

// ---- §D genesis ----

#[test]
fn genesis_seeds_bootstrap_node_and_principal() {
    // Σ₀ + O14: nodes = {[1]}, frontiers = {}, Π = {[1] → π₀}.
    let s = M3State::genesis();
    assert_eq!(s.entity_level(&a(&[1])), Some(Level::Node));
    assert!(s.is_allocated(&a(&[1])));
    let p = s.principal_by_id(BOOTSTRAP_PRINCIPAL).expect("π₀ registered");
    assert_eq!(p.id, BOOTSTRAP_PRINCIPAL);
    assert_eq!(p.prefix, a(&[1]));
    assert_eq!(s.principal_prefix(BOOTSTRAP_PRINCIPAL), Some(a(&[1])));
    // Empty frontiers: nothing else is allocated or registered yet.
    assert!(!s.is_allocated(&a(&[1, 0, 1])));
    assert_eq!(s.entity_level(&a(&[1, 0, 1])), None);
    // Unknown ids resolve to nothing (single-valued scan, §5).
    assert!(s.principal_by_id(ID1).is_none());
    assert!(s.principal_prefix(ID1).is_none());
}

// ---- §A frontier mints ----

#[test]
fn pure_mints_advance_the_documented_chains() {
    let (k, _ns, acct, doc) = with_account_and_doc();
    let snap = k.snapshot();
    let m3 = snap.world().m3();

    // mint_content: namespace (b_C(d), 1), element field [s_C = 1, m+1] (§3).
    let (c1, rec) = m3.mint_content(&doc).expect("content mint");
    assert_eq!(c1, a(&[1, 0, 1, 0, 1, 0, 1, 1]));
    assert_eq!(c1.subspace(), Some(&Nat::from(1u32)));
    // The mint hands back exactly the Allocate for the minted address.
    let M3Rec::Allocate { addr } = rec else {
        panic!("a mint returns M3Rec::Allocate");
    };
    assert_eq!(addr, *c1.tumbler());
    // Determinism (B2): a pure function of the frontier — same state, same
    // answer.
    assert_eq!(m3.mint_content(&doc).expect("repeat").0, c1);

    // mint_link: namespace (b_L(d), 1), s_L = 2 — content↔link address
    // spaces disjoint by construction (SD/L14, T7).
    let (l1, _) = m3.mint_link(&doc).expect("link mint");
    assert_eq!(l1, a(&[1, 0, 1, 0, 1, 0, 2, 1]));
    assert_eq!(l1.subspace(), Some(&Nat::from(2u32)));

    // mint_version: namespace (d, 1) — the version chain, SEPARATE from the
    // document chain (ASN-0123 VD).
    let (v1, _) = m3.mint_version(&doc).expect("version mint");
    assert_eq!(v1, a(&[1, 0, 1, 0, 1, 1]));
    assert_eq!(v1.level(), Level::Document);

    // mint_document: namespace (account, 2) — advances independently of the
    // version chain; no collision (the ASN-0103 fix).
    let (d2, _) = m3.mint_document(&acct).expect("document mint");
    assert_eq!(d2, a(&[1, 0, 1, 0, 2]));
    assert_ne!(d2, v1);
}

#[test]
fn successive_mints_in_one_composite_read_working_state() {
    // The M5-shaped composite (§A / M2 contract 3): lock key taken BEFORE
    // the closure, mints read working() so each sees the prior mint, staged
    // records lifted via .into().
    let (k, _ns, _acct, doc) = with_account_and_doc();
    let keys = [M3State::content_lock_key(&doc)];
    let ((c1, c2), seq) = k
        .transact::<_, MintError>(&keys, |stg| {
            let (c1, r1) = stg.working().m3().mint_content(&doc)?;
            stg.push(r1.into());
            let (c2, r2) = stg.working().m3().mint_content(&doc)?;
            stg.push(r2.into());
            Ok((c1, c2))
        })
        .expect("composite commits");
    assert_eq!(c1, a(&[1, 0, 1, 0, 1, 0, 1, 1]));
    assert_eq!(c2, a(&[1, 0, 1, 0, 1, 0, 1, 2])); // saw the prior mint
    let snap = k.snapshot();
    assert_eq!(snap.seq(), seq);
    assert!(snap.world().m3().is_allocated(&c1));
    assert!(snap.world().m3().is_allocated(&c2));
}

#[test]
fn mint_preconditions_reject_structurally() {
    let (k, _ns, acct, doc) = with_account_and_doc();
    let snap = k.snapshot();
    let m3 = snap.world().m3();
    let ghost_doc = a(&[1, 0, 1, 0, 9]); // document-level, never registered
    let ghost_acct = a(&[1, 0, 9]); // account-level, never registered

    // P6/C2/L1a: content/link home must be a REGISTERED Document.
    assert_eq!(mint_err(m3.mint_content(&ghost_doc)), MintError::HomeNotRegistered);
    assert_eq!(mint_err(m3.mint_link(&ghost_doc)), MintError::HomeNotRegistered);
    assert_eq!(mint_err(m3.mint_content(&acct)), MintError::HomeNotRegistered);
    // V-WF: version source must be a registered Document — covers an
    // unregistered address AND a registered non-document alike.
    assert_eq!(mint_err(m3.mint_version(&ghost_doc)), MintError::SourceNotRegistered);
    assert_eq!(mint_err(m3.mint_version(&acct)), MintError::SourceNotRegistered);
    // P8/CND.pre: document target must be a registered Account — covers
    // unregistered AND non-account (document, node) alike.
    assert_eq!(mint_err(m3.mint_document(&ghost_acct)), MintError::NotAnAccount);
    assert_eq!(mint_err(m3.mint_document(&doc)), MintError::NotAnAccount);
    assert_eq!(mint_err(m3.mint_document(&a(&[1]))), MintError::NotAnAccount);
}

// ---- §C queries: membership ----

#[test]
fn membership_is_exact_chain_membership() {
    let (k, _ns, acct, doc) = with_account_and_doc();
    let snap = k.snapshot();
    let m3 = snap.world().m3();

    // Ghost principle (B3): a registered-empty document is an addressable
    // ghost — allocated with no content ever minted.
    assert!(m3.is_allocated(&doc));
    assert!(m3.is_registered_document(&doc));
    assert_eq!(m3.entity_level(&doc), Some(Level::Document));
    assert_eq!(m3.entity_level(&acct), Some(Level::Account));

    // Exact range membership (§2): the ordinal past the frontier is out.
    assert!(!m3.is_allocated(&a(&[1, 0, 1, 0, 2])));
    assert!(!m3.is_allocated(&a(&[1, 0, 2])));
    assert_eq!(m3.entity_level(&a(&[1, 0, 1, 0, 2])), None);
    assert!(!m3.is_registered_document(&a(&[1, 0, 1, 0, 2])));

    // Content elements: unallocated before their mint, allocated after —
    // and NEVER entities (content/link are not in E; use is_allocated).
    let c1 = a(&[1, 0, 1, 0, 1, 0, 1, 1]);
    assert!(!m3.is_allocated(&c1));
    let keys = [M3State::content_lock_key(&doc)];
    k.transact::<_, MintError>(&keys, |stg| {
        let (_, r) = stg.working().m3().mint_content(&doc)?;
        stg.push(r.into());
        Ok(())
    })
    .expect("content commit");
    let snap = k.snapshot();
    let m3 = snap.world().m3();
    assert!(m3.is_allocated(&c1));
    assert_eq!(m3.entity_level(&c1), None);
    assert!(!m3.is_registered_document(&c1));
    // Its sibling one past the frontier is not allocated.
    assert!(!m3.is_allocated(&a(&[1, 0, 1, 0, 1, 0, 1, 2])));
}

// ---- §A lock keys ----

#[test]
fn lock_keys_distinguish_every_chain_and_registry() {
    let acct = a(&[1, 0, 1]);
    let doc = a(&[1, 0, 1, 0, 1]);
    // The three g=1 chains under ONE document — content (b_C(d),1), link
    // (b_L(d),1), version (d,1) — plus the document chain and the two
    // registry keys: all pairwise distinct (B7/B8; §1/§8 — an alias would
    // under-serialize a namespace and reuse an address).
    let keys = [
        M3State::content_lock_key(&doc),
        M3State::link_lock_key(&doc),
        M3State::version_lock_key(&doc),
        M3State::document_lock_key(&acct),
        M3State::principals_lock_key(),
        M3State::node_lock_key(),
    ];
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(keys[i], keys[j], "lock keys {i} and {j} alias");
        }
    }
    // g distinguishes the two chains anchored at the SAME tumbler: an
    // account's version-style (A,1) sub-account chain vs its (A,2) document
    // chain (ASN-0123 separation falls out of the key).
    assert_ne!(
        M3State::version_lock_key(&acct),
        M3State::document_lock_key(&acct)
    );
    // Distinct homes get distinct keys.
    assert_ne!(
        M3State::content_lock_key(&doc),
        M3State::content_lock_key(&a(&[1, 0, 1, 0, 2]))
    );
}

// ---- §C queries: ownership ----

#[test]
fn owns_is_containment_effective_owner_is_authorization() {
    let (k, _ns, acct, doc) = with_account_and_doc();
    let snap = k.snapshot();
    let m3 = snap.world().m3();

    // O1: bare containment is true for SEVERAL principals at once — the
    // node operator's prefix contains the delegated account and its
    // documents…
    assert!(M3State::owns(&a(&[1]), &acct));
    assert!(M3State::owns(&a(&[1]), &doc));
    assert!(M3State::owns(&acct, &doc));
    assert!(M3State::owns(&acct, &acct)); // ≼ admits equality
    assert!(!M3State::owns(&acct, &a(&[1])));
    // …so only ω (longest-prefix match) arbitrates: the delegate owns its
    // subtree, the node operator keeps the rest (O2/O3, the
    // ownership-divergence discipline).
    assert_eq!(m3.effective_owner(&doc).expect("covered").id, ID1);
    assert_eq!(m3.effective_owner(&acct).expect("covered").id, ID1);
    assert_eq!(
        m3.effective_owner(&a(&[1])).expect("covered").id,
        BOOTSTRAP_PRINCIPAL
    );
    // ω is a pure prefix query — valid even for not-yet-allocated addresses.
    assert_eq!(
        m3.effective_owner(&a(&[1, 0, 2])).expect("covered").id,
        BOOTSTRAP_PRINCIPAL
    );
    assert_eq!(
        m3.effective_owner(&a(&[1, 0, 1, 0, 9, 0, 1, 5]))
            .expect("covered")
            .id,
        ID1
    );
    // Uncovered (a foreign node's subtree): None.
    assert!(m3.effective_owner(&a(&[2])).is_none());
    assert!(m3.effective_owner(&a(&[2, 0, 1])).is_none());
}

// ---- §B delegate ----

#[test]
fn delegate_mints_account_and_principal_atomically() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(Arc::clone(&k));

    // The peek names the exact next-form value delegate demands (O17c) —
    // no guess-and-retry.
    let peek = k
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&a(&[1]))
        .expect("node peek");
    assert_eq!(peek, a(&[1, 0, 1]));

    let before = k.current_seq();
    let (acct, seq) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, peek.tumbler().clone(), ID1)
        .expect("delegate");
    assert_eq!(acct, peek);
    assert!(seq > before);
    assert_eq!(k.current_seq(), seq); // the committed last_seq

    // Both halves landed in ONE transaction (O17b): the allocation and the
    // principal.
    let snap = k.snapshot();
    let m3 = snap.world().m3();
    assert!(m3.is_allocated(&acct));
    assert_eq!(m3.entity_level(&acct), Some(Level::Account));
    assert_eq!(m3.principal_prefix(ID1), Some(acct.clone()));
    // Effective ownership moved to the new principal (O7).
    assert_eq!(m3.effective_owner(&acct).expect("covered").id, ID1);
    // The node's account chain peeks the next slot now.
    assert_eq!(m3.next_account_prefix(&a(&[1])), Some(a(&[1, 0, 2])));

    // Sub-account delegation on the account's own (A, 1) chain — the sixth
    // chain family (Conflicts §8).
    let sub = m3.next_account_prefix(&acct).expect("account peek");
    assert_eq!(sub, a(&[1, 0, 1, 1]));
    let (sub_acct, _) = ns
        .delegate(ID1, sub.tumbler().clone(), ID2)
        .expect("sub-delegate");
    assert_eq!(sub_acct, sub);
    let snap = k.snapshot();
    let m3 = snap.world().m3();
    assert_eq!(m3.effective_owner(&sub_acct).expect("covered").id, ID2);
    // ω still refines by longest match beside the sub-account.
    assert_eq!(
        m3.effective_owner(&a(&[1, 0, 1, 2])).expect("covered").id,
        ID1
    );

    // next_account_prefix: None unless the parent is a REGISTERED node or
    // account.
    assert!(m3.next_account_prefix(&a(&[1, 0, 9])).is_none());
    let (doc, _) = ns.create_new_document(ID1, &acct).expect("create");
    assert!(k
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&doc)
        .is_none());
}

#[test]
fn delegate_rejection_order_is_pinned() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(Arc::clone(&k));
    let unknown = PrincipalId(99);

    // Pre-work rejections (§6, no transaction opened) win over every
    // in-closure condition — here the delegator is ALSO unknown:
    // NotValid (validate-lift; [1,0] has a trailing zero)…
    assert_eq!(
        rejected(ns.delegate(unknown, t(&[1, 0]), ID1)),
        DelegateError::NotValid
    );
    // …then NotAccountTier (hoisted (iii)): a bare node prefix is T4-VALID
    // but parentless — the hoist must reject it typed, before any
    // namespace()/lock-key construction (no panic), and a document-tier
    // prefix is equally out (zeros == 1, narrowed from O15's ≤ 1).
    assert_eq!(
        rejected(ns.delegate(unknown, t(&[2]), ID1)),
        DelegateError::NotAccountTier
    );
    assert_eq!(
        rejected(ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1, 0, 1]), ID1)),
        DelegateError::NotAccountTier
    );
    // DelegatorUnknown: the first in-closure gate.
    assert_eq!(
        rejected(ns.delegate(unknown, t(&[1, 0, 1]), ID1)),
        DelegateError::DelegatorUnknown
    );

    ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("delegate [1,0,1] → ID1");

    // NotAncestor (i): ID1's prefix [1,0,1] does not contain [1,0,2] — and
    // (ii) would also fail (ω([1,0,2]) = π₀), so this pins (i) before (ii).
    assert_eq!(
        rejected(ns.delegate(ID1, t(&[1, 0, 2]), ID2)),
        DelegateError::NotAncestor
    );
    // NotAuthorized (ii): π₀ is an ancestor of [1,0,1,1], but ω resolves
    // the delegate ID1 (longest match), not the ancestor.
    assert_eq!(
        rejected(ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1, 1]), ID2)),
        DelegateError::NotAuthorized
    );
    // DuplicateId: a reused id rejects even though [1,0,3] is fresh AND not
    // next-form — DuplicateId precedes NotNextForm.
    assert_eq!(
        rejected(ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 3]), ID1)),
        DelegateError::DuplicateId
    );
    // NotNextForm (O17c): fresh prefix, fresh id, registered parent — but
    // the (N, 2) frontier's next is [1,0,2].
    assert_eq!(
        rejected(ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 3]), ID2)),
        DelegateError::NotNextForm
    );
    // A rejected delegation commits NEITHER half (clean typed rejection).
    let snap = k.snapshot();
    assert!(!snap.world().m3().is_allocated(&a(&[1, 0, 3])));
    assert!(snap.world().m3().principal_by_id(ID2).is_none());

    // ParentNotRegistered (P8, Conflicts §5) — on a FRESH kernel π₀ is ω of
    // [1,0,1,1] and that chain's next-form is satisfied, so the unregistered
    // parent is the only failing gate; with [1,0,1,2] it also precedes
    // NotNextForm.
    let k2 = mem_kernel(genesis_world());
    let ns2 = Namespace::new(Arc::clone(&k2));
    assert_eq!(
        rejected(ns2.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1, 1]), ID2)),
        DelegateError::ParentNotRegistered
    );
    assert_eq!(
        rejected(ns2.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1, 2]), ID2)),
        DelegateError::ParentNotRegistered
    );
    // id-freshness guards the bootstrap id too: no later principal may
    // re-claim id 0 (§7).
    assert_eq!(
        rejected(ns2.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), BOOTSTRAP_PRINCIPAL)),
        DelegateError::DuplicateId
    );

    // NotFresh and NotTopDown need an allocated-but-principal-less account;
    // the fold admits exactly the record shapes delegate itself stages
    // (apply_ns totality domain), so seed one directly.
    let seeded = World {
        m3: M3State::genesis().apply_ns(&alloc(&[1, 0, 1])),
    };
    let k3 = mem_kernel(seeded);
    let ns3 = Namespace::new(Arc::clone(&k3));
    // (v) freshness: [1,0,1] is allocated (ω = π₀, so (ii) passes).
    assert_eq!(
        rejected(ns3.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID2)),
        DelegateError::NotFresh
    );
    // (iv) top-down: with a principal strictly under [1,0,1] the same call
    // rejects NotTopDown — which precedes NotFresh (the input violates
    // both).
    let seeded = World {
        m3: M3State::genesis()
            .apply_ns(&alloc(&[1, 0, 1]))
            .apply_ns(&alloc(&[1, 0, 1, 1]))
            .apply_ns(&M3Rec::RegisterPrincipal {
                prefix: t(&[1, 0, 1, 1]),
                id: ID2,
            }),
    };
    let k4 = mem_kernel(seeded);
    let ns4 = Namespace::new(Arc::clone(&k4));
    assert_eq!(
        rejected(ns4.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), PrincipalId(7))),
        DelegateError::NotTopDown
    );
}

// ---- §B create_new_document ----

#[test]
fn create_new_document_authorizes_by_omega() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(Arc::clone(&k));
    let (acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("delegate");

    // Ordinary: the effective owner baptizes documents in chain order.
    let (d1, s1) = ns.create_new_document(ID1, &acct).expect("create 1");
    let (d2, s2) = ns.create_new_document(ID1, &acct).expect("create 2");
    assert_eq!(d1, a(&[1, 0, 1, 0, 1]));
    assert_eq!(d2, a(&[1, 0, 1, 0, 2]));
    assert!(s2 > s1);
    assert!(k.snapshot().world().m3().is_registered_document(&d1));

    // The ownership-divergence trap (O5): π₀'s prefix CONTAINS the account
    // (owns = true), yet ω names ID1 — bare containment must not authorize.
    assert!(M3State::owns(&a(&[1]), &acct));
    assert_eq!(
        rejected(ns.create_new_document(BOOTSTRAP_PRINCIPAL, &acct)),
        OpError::NotOwner
    );
    // An unknown caller is the effective owner of nothing.
    assert_eq!(
        rejected(ns.create_new_document(PrincipalId(99), &acct)),
        OpError::NotOwner
    );
    // ω-auth is evaluated FIRST (§7): a non-owner of an unregistered
    // account gets NotOwner, while the owner (π₀ covers all unregistered
    // prefixes under [1]) reaches the structural mint gate — NotAnAccount
    // covers unregistered and node-tier targets alike.
    assert_eq!(
        rejected(ns.create_new_document(ID1, &a(&[1, 0, 2]))),
        OpError::NotOwner
    );
    assert_eq!(
        rejected(ns.create_new_document(BOOTSTRAP_PRINCIPAL, &a(&[1, 0, 2]))),
        OpError::Mint(MintError::NotAnAccount)
    );
    assert_eq!(
        rejected(ns.create_new_document(BOOTSTRAP_PRINCIPAL, &a(&[1]))),
        OpError::Mint(MintError::NotAnAccount)
    );
}

// ---- §B fork ----

#[test]
fn fork_mints_in_the_callers_own_account() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(Arc::clone(&k));
    let (acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("delegate");

    // O10, account-tier: reduces to create_new_document(caller,
    // pfx(caller)) — a fresh self-owned document one tier below the prefix.
    let (d1, _) = ns.fork(ID1).expect("fork");
    assert_eq!(d1, a(&[1, 0, 1, 0, 1]));
    assert!(M3State::owns(&acct, &d1));
    let snap = k.snapshot();
    assert!(snap.world().m3().is_registered_document(&d1));
    assert_eq!(snap.world().m3().effective_owner(&d1).expect("covered").id, ID1);
    // Shares the (account, 2) chain with create_new_document.
    let (d2, _) = ns.create_new_document(ID1, &acct).expect("create");
    assert_eq!(d2, a(&[1, 0, 1, 0, 2]));

    // Unknown id: typed NotOwner (an unregistered caller owns nothing).
    assert_eq!(rejected(ns.fork(PrincipalId(99))), OpError::NotOwner);
    // Node-tier caller (π₀ at [1]): the node-tier O10 case is DROPPED —
    // typed Mint(NotAnAccount), never a silent skip (Conflicts §6).
    assert_eq!(
        rejected(ns.fork(BOOTSTRAP_PRINCIPAL)),
        OpError::Mint(MintError::NotAnAccount)
    );
}

// ---- §B register_node ----

#[test]
fn register_node_validates_and_admits_supplied_addresses() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(Arc::clone(&k));

    // Ordinary admission (ASN-0047): the address is SUPPLIED, validated,
    // registered.
    let (n, seq) = ns.register_node(t(&[1, 7])).expect("register");
    assert_eq!(n, a(&[1, 7]));
    assert_eq!(k.current_seq(), seq);
    let snap = k.snapshot();
    let m3 = snap.world().m3();
    assert_eq!(m3.entity_level(&n), Some(Level::Node));
    assert!(m3.is_allocated(&n));
    // A provisioned node stays bootstrap-owned via ω until an account is
    // delegated beneath it (Conflicts §7)…
    assert_eq!(
        m3.effective_owner(&n).expect("covered").id,
        BOOTSTRAP_PRINCIPAL
    );
    // …and delegation beneath it works through the ordinary gate.
    let peek = m3.next_account_prefix(&n).expect("peek under new node");
    assert_eq!(peek, a(&[1, 7, 0, 1]));
    ns.delegate(BOOTSTRAP_PRINCIPAL, peek.tumbler().clone(), ID1)
        .expect("delegate under the new node");

    // Rejections, in the documented guard order:
    // NotValid — not T4 ([1,0] has a trailing zero).
    assert_eq!(rejected(ns.register_node(t(&[1, 0]))), NodeError::NotValid);
    // NotNode — account-level input; checked before lineage ([2,0,1] is
    // also not bootstrap-descended).
    assert_eq!(rejected(ns.register_node(t(&[2, 0, 1]))), NodeError::NotNode);
    // NotFresh — duplicates surface typed, never a silent coalesce; the
    // seeded [1] and the just-registered [1,7] alike.
    assert_eq!(rejected(ns.register_node(t(&[1]))), NodeError::NotFresh);
    assert_eq!(rejected(ns.register_node(t(&[1, 7]))), NodeError::NotFresh);
    // NotDescendantOfBootstrap — [1] ≼ addr fails.
    assert_eq!(
        rejected(ns.register_node(t(&[2]))),
        NodeError::NotDescendantOfBootstrap
    );
}

// ---- serde / recovery ----

#[test]
fn journaled_types_survive_serde_round_trips() {
    // M3Rec — the journal delta — through M2's actual wire format (bincode).
    let recs = [
        M3Rec::Allocate { addr: t(&[1, 0, 1]) },
        M3Rec::RegisterNode { addr: t(&[1, 7]) },
        M3Rec::RegisterPrincipal {
            prefix: t(&[1, 0, 1]),
            id: ID1,
        },
    ];
    for rec in &recs {
        let bytes = bincode::serialize(rec).expect("serialize M3Rec");
        let back: M3Rec = bincode::deserialize(&bytes).expect("deserialize M3Rec");
        match (rec, &back) {
            (M3Rec::Allocate { addr: x }, M3Rec::Allocate { addr: y }) => assert_eq!(x, y),
            (M3Rec::RegisterNode { addr: x }, M3Rec::RegisterNode { addr: y }) => {
                assert_eq!(x, y)
            }
            (
                M3Rec::RegisterPrincipal { prefix: x, id: i },
                M3Rec::RegisterPrincipal { prefix: y, id: j },
            ) => {
                assert_eq!(x, y);
                assert_eq!(i, j);
            }
            _ => panic!("variant changed across the round trip"),
        }
    }

    // M3State — the checkpointed slice: every field is ordinary serde (none
    // skip-serialized; default rebuild_derived), so a round-tripped state
    // answers identically.
    let (k, _ns, acct, doc) = with_account_and_doc();
    let keys = [M3State::content_lock_key(&doc)];
    k.transact::<_, MintError>(&keys, |stg| {
        let (_, r) = stg.working().m3().mint_content(&doc)?;
        stg.push(r.into());
        Ok(())
    })
    .expect("content commit");
    let state = k.snapshot().world().m3().clone();
    let bytes = bincode::serialize(&state).expect("serialize M3State");
    let back: M3State = bincode::deserialize(&bytes).expect("deserialize M3State");
    assert!(back.is_allocated(&a(&[1, 0, 1, 0, 1, 0, 1, 1])));
    assert!(back.is_registered_document(&doc));
    assert_eq!(back.entity_level(&acct), Some(Level::Account));
    assert_eq!(back.principal_prefix(ID1), Some(acct.clone()));
    assert_eq!(back.effective_owner(&doc).expect("covered").id, ID1);
    assert_eq!(back.next_account_prefix(&a(&[1])), Some(a(&[1, 0, 2])));

    // Principal (id + prefix) rides inside the slice; round-trip it directly.
    let p = back.principal_by_id(BOOTSTRAP_PRINCIPAL).expect("π₀");
    let bytes = bincode::serialize(&p).expect("serialize Principal");
    let q: Principal = bincode::deserialize(&bytes).expect("deserialize Principal");
    assert_eq!(q.id, p.id);
    assert_eq!(q.prefix, p.prefix);
}

#[test]
fn durable_kernel_recovers_the_registry_by_checkpoint_and_replay() {
    // M3 rides M2 (§8): its slice is restored verbatim from the loaded
    // checkpoint, then advanced by replaying post-checkpoint M3Recs (default
    // rebuild_derived — nothing to re-seed).
    let dir = tempdir().expect("tempdir");
    let acct;
    let doc;
    {
        let k = Arc::new(Kernel::open(cfg_fsync(dir.path()), genesis_world()).expect("open"));
        let ns = Namespace::new(Arc::clone(&k));
        let (acc, _) = ns
            .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
            .expect("delegate");
        acct = acc;
        // Checkpoint here: the delegation is restored FROM the checkpoint;
        // everything after rides post-checkpoint replay.
        k.checkpoint().expect("checkpoint");
        let (d, _) = ns.create_new_document(ID1, &acct).expect("create");
        doc = d;
        ns.register_node(t(&[1, 7])).expect("register node");
    }
    let k2 = Kernel::open(cfg_fsync(dir.path()), genesis_world()).expect("reopen");
    let snap = k2.snapshot();
    let m3 = snap.world().m3();
    assert_eq!(m3.principal_prefix(ID1), Some(acct.clone()));
    assert!(m3.is_registered_document(&doc));
    assert_eq!(m3.entity_level(&a(&[1, 7])), Some(Level::Node));
    assert_eq!(m3.effective_owner(&doc).expect("covered").id, ID1);
    // The frontiers recovered too: the chains continue where they left off.
    assert_eq!(m3.next_account_prefix(&a(&[1])), Some(a(&[1, 0, 2])));
    let (d2, _) = m3.mint_document(&acct).expect("mint after recovery");
    assert_eq!(d2, a(&[1, 0, 1, 0, 2]));
}
