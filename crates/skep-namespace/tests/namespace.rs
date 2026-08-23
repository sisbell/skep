//! Integration tests for M3's public surface. Each test states a claim the
//! design/interface actually makes (§-references inline): what constructors
//! and gates admit and reject, which rejection wins on a multiply-defective
//! input (the pinned orders), that the journaled types survive a serde round
//! trip, and that each part of the interface does its ordinary job. The toy
//! `World`/`Rec` pair is the minimal engine assembly the composition
//! contract prescribes: `HasM3` read accessor, `From<M3Rec>` record lift,
//! `apply` dispatching into `M3State::apply_m3`.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use skep_address::{
    content_subspace, link_subspace, validate, Address, Level, Nat, Tumbler,
};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelConfig, LockKey, TxnError,
    WorldState,
};
use skep_namespace::{
    prefix_contains, CreateDocumentError, DelegateError, HasM3, M3Rec, M3State, MintError,
    Namespace, NodeError, PrincipalId, BOOTSTRAP_PRINCIPAL, MAX_NODE_COMPONENTS,
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
            m3: self.m3.apply_m3(&r.0),
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
    M3Rec::Allocate { addr: a(comps) }
}

fn genesis_world() -> World {
    World {
        m3: M3State::genesis(),
    }
}

fn mem_kernel(genesis: World) -> Arc<Kernel<World>> {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
    };
    Arc::new(Kernel::open(cfg, genesis).expect("in-memory open"))
}

fn fsync_config(dir: &Path) -> KernelConfig {
    KernelConfig {
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

/// Mint under the matching lock key, stage the returned record, commit — the
/// M5/M7-shaped composite in one line, so a test can say what a chain does
/// once its records actually reach the fold.
fn commit_mint(
    k: &Kernel<World>,
    key: LockKey,
    mint: impl FnOnce(&M3State) -> Result<(Address, M3Rec), MintError>,
) -> Address {
    k.transact::<_, MintError>(&[key], |stg| {
        let (addr, rec) = mint(stg.working().m3())?;
        stg.push(rec.into());
        Ok(addr)
    })
    .expect("the mint commits")
    .0
}

const ID1: PrincipalId = PrincipalId(1);
const ID2: PrincipalId = PrincipalId(2);
/// An id no principal in any fixture carries — the caller every op must
/// refuse, and the ω no address resolves to.
const UNKNOWN_ID: PrincipalId = PrincipalId(99);

/// The standard fixture: genesis, then `delegate [1,0,1] → ID1`, then
/// `create_new_document` under it (⇒ doc `[1,0,1,0,1]`). The handle borrows
/// the kernel, so it stays inside; a test that needs one builds it off the
/// returned kernel.
fn kernel_with_account_and_doc() -> (Arc<Kernel<World>>, Address, Address) {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let (acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("bootstrap delegates the first account");
    let (doc, _) = ns
        .create_new_document(ID1, &acct)
        .expect("the delegate creates a document");
    (k, acct, doc)
}

// ---- §D genesis ----

#[test]
fn genesis_seeds_bootstrap_node_and_principal() {
    // Σ₀ + O14: nodes = {[1]}, frontiers = {}, Π = {[1] → π₀}.
    let s = M3State::genesis();
    assert_eq!(s.entity_level(&a(&[1])), Some(Level::Node));
    assert!(s.is_allocated(&a(&[1])));
    // π₀ resolves in both directions: its id names the root prefix, and the
    // root address names it as ω.
    assert_eq!(s.principal_prefix(BOOTSTRAP_PRINCIPAL), Some(&a(&[1])));
    assert_eq!(s.effective_owner(&a(&[1])), Some(BOOTSTRAP_PRINCIPAL));
    // Empty frontiers: nothing else is allocated or registered yet.
    assert!(!s.is_allocated(&a(&[1, 0, 1])));
    assert_eq!(s.entity_level(&a(&[1, 0, 1])), None);
    // Unknown ids resolve to nothing (single-valued scan, §5).
    assert!(s.principal_prefix(ID1).is_none());
    assert!(!s.is_effective_owner(ID1, &a(&[1])));
}

#[test]
fn the_slice_prints_its_three_registries_and_their_contents() {
    // The slice a world embeds is reportable, so a test failure or a `dbg!`
    // in any engine can print it — the impl has to live here, since no
    // downstream crate may add it.
    let dump = format!("{:?}", M3State::genesis());
    for field in ["frontiers", "nodes", "principals"] {
        assert!(dump.contains(field), "the dump omits {field}: {dump}");
    }
    // The contents ride along, not just the field names: the bootstrap
    // principal's id and its root prefix.
    assert!(dump.contains("PrincipalId(0)"), "{dump}");
    assert_eq!(format!("{:?}", M3State::genesis()), dump); // deterministic
}

// ---- §A frontier mints ----

#[test]
fn pure_mints_advance_the_documented_chains() {
    let (k, acct, doc) = kernel_with_account_and_doc();
    let snap = k.snapshot();
    let m3 = snap.world().m3();

    // mint_content: namespace (b_C(d), 1), element field [s_C = 1, m+1] (§3).
    let (c1, rec) = m3.mint_content(&doc).expect("content mint");
    assert_eq!(c1, a(&[1, 0, 1, 0, 1, 0, 1, 1]));
    assert_eq!(c1.subspace(), Some(&content_subspace()));
    // The mint hands back exactly the Allocate for the minted address —
    // whole value, variant and payload alike.
    assert_eq!(rec, M3Rec::Allocate { addr: c1.clone() });
    // Determinism (B2): a pure function of the frontier — same state, same
    // answer.
    assert_eq!(m3.mint_content(&doc).expect("repeat").0, c1);

    // mint_link: namespace (b_L(d), 1), s_L = 2 — content↔link address
    // spaces disjoint by construction (SD/L14, T7).
    let (l1, _) = m3.mint_link(&doc).expect("link mint");
    assert_eq!(l1, a(&[1, 0, 1, 0, 1, 0, 2, 1]));
    assert_eq!(l1.subspace(), Some(&link_subspace()));

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
    let (k, _acct, doc) = kernel_with_account_and_doc();
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
fn every_chain_survives_the_round_trip_from_mint_to_allocated() {
    // §1/§2: the key a mint READS and the key its staged Allocate ADVANCES
    // are one key, so a minted address is allocated once the fold has seen
    // it and the NEXT mint on that chain differs from it. A divergence
    // between the two derivations would re-hand a live address — the one
    // fatal error — without any mint or query saying so.
    let (k, acct, doc) = kernel_with_account_and_doc();

    // Version chain (d, 1) — ASN-0123's separate chain.
    let v1 = commit_mint(&k, M3State::version_lock_key(&doc), |m3| m3.mint_version(&doc));
    assert_eq!(v1, a(&[1, 0, 1, 0, 1, 1]));
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.is_allocated(&v1));
    // A version IS a registered Document — the M5 CREATENEWVERSION seam.
    assert!(m3.is_registered_document(&v1));
    assert_eq!(m3.entity_level(&v1), Some(Level::Document));
    // The frontier advanced, so the chain does not re-mint v1.
    let v2 = commit_mint(&k, M3State::version_lock_key(&doc), |m3| m3.mint_version(&doc));
    assert_eq!(v2, a(&[1, 0, 1, 0, 1, 2]));
    assert!(k.snapshot().world().m3().is_allocated(&v2));

    // Link chain (b_L(d), 1) — allocated, and NEVER an entity.
    let l1 = commit_mint(&k, M3State::link_lock_key(&doc), |m3| m3.mint_link(&doc));
    let l2 = commit_mint(&k, M3State::link_lock_key(&doc), |m3| m3.mint_link(&doc));
    assert_eq!(l1, a(&[1, 0, 1, 0, 1, 0, 2, 1]));
    assert_eq!(l2, a(&[1, 0, 1, 0, 1, 0, 2, 2]));
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.is_allocated(&l1) && m3.is_allocated(&l2));
    assert_eq!(m3.entity_level(&l1), None);

    // A version is a usable home in its own right: it carries content and
    // versions of its own, on chains anchored at IT.
    let c = commit_mint(&k, M3State::content_lock_key(&v1), |m3| m3.mint_content(&v1));
    assert_eq!(c, a(&[1, 0, 1, 0, 1, 1, 0, 1, 1]));
    let vv = commit_mint(&k, M3State::version_lock_key(&v1), |m3| m3.mint_version(&v1));
    assert_eq!(vv, a(&[1, 0, 1, 0, 1, 1, 1]));
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.is_allocated(&c) && m3.is_allocated(&vv));

    // Through all of it the document chain (A, 2) stood still — the ASN-0123
    // separation, now checked across real folds rather than one snapshot.
    assert_eq!(
        m3.mint_document(&acct).expect("document mint").0,
        a(&[1, 0, 1, 0, 2])
    );
}

#[test]
fn a_mint_whose_record_is_never_staged_re_hands_its_address() {
    // §A: advancing the frontier is the CALLER's half of every mint, and
    // nothing in M3 can enforce it — the record is delivered inside a tuple
    // the caller has already destructured. This is that obligation made
    // executable rather than left as prose: drop the record and the very next
    // mint on the chain returns the SAME address, with no error and no query
    // saying so. The fold's contiguity check cannot see it either, since the
    // second Allocate would be a legitimate m + 1.
    let (k, _acct, doc) = kernel_with_account_and_doc();
    let key = M3State::content_lock_key(&doc);

    // A composite that mints and commits without staging: it commits, and it
    // moves nothing.
    let (dropped, _) = k
        .transact::<_, MintError>(std::slice::from_ref(&key), |stg| {
            Ok(stg.working().m3().mint_content(&doc)?.0)
        })
        .expect("the transaction commits");
    assert_eq!(dropped, a(&[1, 0, 1, 0, 1, 0, 1, 1]));
    assert!(!k.snapshot().world().m3().is_allocated(&dropped));

    // …so the chain hands the address out a second time — the reuse the
    // caller's half exists to prevent, and which M3 alone cannot.
    let staged = commit_mint(&k, key, |m3| m3.mint_content(&doc));
    assert_eq!(staged, dropped);
    assert!(k.snapshot().world().m3().is_allocated(&staged));
}

#[test]
fn the_allocator_never_repeats_an_address_across_an_interleaved_schedule() {
    // B1/B2 as laws, not examples: over a mechanical round-robin across the
    // four chains, every minted address is distinct and allocated, the next
    // mint on each chain is still fresh, and the whole schedule is
    // deterministic.
    fn run() -> (Arc<Kernel<World>>, Vec<Address>, Address, Address) {
        let (k, acct, doc) = kernel_with_account_and_doc();
        let keys = [
            M3State::content_lock_key(&doc),
            M3State::link_lock_key(&doc),
            M3State::version_lock_key(&doc),
            M3State::document_lock_key(&acct),
        ];
        let mut minted = Vec::new();
        for _round in 0..5 {
            let four = k
                .transact::<_, MintError>(&keys, |stg| {
                    let (c, rc) = stg.working().m3().mint_content(&doc)?;
                    stg.push(rc.into());
                    let (l, rl) = stg.working().m3().mint_link(&doc)?;
                    stg.push(rl.into());
                    let (v, rv) = stg.working().m3().mint_version(&doc)?;
                    stg.push(rv.into());
                    let (d, rd) = stg.working().m3().mint_document(&acct)?;
                    stg.push(rd.into());
                    Ok(vec![c, l, v, d])
                })
                .expect("the round commits")
                .0;
            minted.extend(four);
        }
        (k, minted, acct, doc)
    }

    let (k, minted, acct, doc) = run();
    // Never reused: 20 mints, 20 distinct addresses (across chains as well
    // as within one).
    let distinct: std::collections::BTreeSet<&Address> = minted.iter().collect();
    assert_eq!(
        distinct.len(),
        minted.len(),
        "an address was minted twice: {minted:?}"
    );
    // Every one of them is allocated.
    let m3 = k.snapshot().world().m3().clone();
    for addr in &minted {
        assert!(m3.is_allocated(addr), "{addr:?} was minted but is not allocated");
    }
    // Gap-free and monotone per chain: the next mint on each chain is an
    // address the schedule has not already handed out, and is not yet
    // allocated.
    for (chain, next) in [
        ("content", m3.mint_content(&doc).expect("peek").0),
        ("link", m3.mint_link(&doc).expect("peek").0),
        ("version", m3.mint_version(&doc).expect("peek").0),
        ("document", m3.mint_document(&acct).expect("peek").0),
    ] {
        assert!(!minted.contains(&next), "{chain}: the next mint repeats {next:?}");
        assert!(
            !m3.is_allocated(&next),
            "{chain}: the next mint is already allocated"
        );
    }
    // Determinism (B2): the same schedule from genesis yields the same list.
    let (_k2, again, _, _) = run();
    assert_eq!(minted, again);
}

#[test]
fn mint_preconditions_reject_structurally() {
    let (k, acct, doc) = kernel_with_account_and_doc();
    let snap = k.snapshot();
    let m3 = snap.world().m3();
    let unregistered_doc = a(&[1, 0, 1, 0, 9]); // document-level, never registered
    let unregistered_acct = a(&[1, 0, 9]); // account-level, never registered

    // P6/C2/L1a: content/link home must be a REGISTERED Document.
    assert_eq!(m3.mint_content(&unregistered_doc).unwrap_err(), MintError::HomeNotRegistered);
    assert_eq!(m3.mint_link(&unregistered_doc).unwrap_err(), MintError::HomeNotRegistered);
    assert_eq!(m3.mint_content(&acct).unwrap_err(), MintError::HomeNotRegistered);
    // V-WF: version source must be a registered Document — covers an
    // unregistered address AND a registered non-document alike.
    assert_eq!(m3.mint_version(&unregistered_doc).unwrap_err(), MintError::SourceNotRegistered);
    assert_eq!(m3.mint_version(&acct).unwrap_err(), MintError::SourceNotRegistered);
    // P8/CND.pre: document target must be a registered Account — covers
    // unregistered AND non-account (document, node) alike.
    assert_eq!(m3.mint_document(&unregistered_acct).unwrap_err(), MintError::NotAnAccount);
    assert_eq!(m3.mint_document(&doc).unwrap_err(), MintError::NotAnAccount);
    assert_eq!(m3.mint_document(&a(&[1])).unwrap_err(), MintError::NotAnAccount);
}

#[test]
fn a_mint_refusal_lifts_into_the_document_rejection() {
    // The shared mint vocabulary lifts by the standard conversion, so a mint
    // composes with `?` inside an op that creates a document — the same lift
    // M5 and M7 provide into their own op errors.
    fn create(m3: &M3State, account: &Address) -> Result<Address, CreateDocumentError> {
        Ok(m3.mint_document(account)?.0)
    }
    let (k, acct, doc) = kernel_with_account_and_doc();
    let snap = k.snapshot();
    let m3 = snap.world().m3();
    assert_eq!(create(m3, &acct), Ok(a(&[1, 0, 1, 0, 2])));
    assert_eq!(
        create(m3, &doc),
        Err(CreateDocumentError::Mint(MintError::NotAnAccount))
    );
}

// ---- §C queries: membership ----

#[test]
fn membership_is_exact_chain_membership() {
    let (k, acct, doc) = kernel_with_account_and_doc();
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

    // No FALSE positives (§2): the near-misses of an allocated content
    // element all decompose to a DIFFERENT namespace, so none is a member —
    // membership is genuine chain membership, not an approximation of it.
    for near in [
        a(&[1, 0, 1, 0, 1, 0, 1]),       // b_C(d) — the chain's own anchor
        a(&[1, 0, 1, 0, 1, 0, 2]),       // b_L(d) — the link anchor
        a(&[1, 0, 1, 0, 1, 0, 2, 1]),    // the same ordinal in the link subspace
        a(&[1, 0, 1, 0, 1, 0, 1, 1, 1]), // one component deeper than c1
        a(&[1, 0, 1, 0, 2, 0, 1, 1]),    // the same ordinal under a sibling doc
        a(&[1, 0, 1, 0, 1, 1]),          // the version chain's first slot
    ] {
        assert!(
            !m3.is_allocated(&near),
            "{near:?} is not allocated but reads as a member"
        );
    }
    assert!(m3.is_allocated(&c1)); // …while the real member still is
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
fn containment_is_not_authorization() {
    let (k, acct, doc) = kernel_with_account_and_doc();
    let snap = k.snapshot();
    let m3 = snap.world().m3();

    // O1: bare containment is true for SEVERAL principals at once — the
    // node operator's prefix contains the delegated account and its
    // documents…
    assert!(prefix_contains(&a(&[1]), &acct));
    assert!(prefix_contains(&a(&[1]), &doc));
    assert!(prefix_contains(&acct, &doc));
    assert!(prefix_contains(&acct, &acct)); // ≼ admits equality
    assert!(!prefix_contains(&acct, &a(&[1])));
    // …so only ω (longest-prefix match) arbitrates: the delegate owns its
    // subtree, the node operator keeps the rest (O2/O3, the
    // ownership-divergence discipline).
    assert_eq!(m3.effective_owner(&doc), Some(ID1));
    assert_eq!(m3.effective_owner(&acct), Some(ID1));
    assert_eq!(m3.effective_owner(&a(&[1])), Some(BOOTSTRAP_PRINCIPAL));
    // ω is a pure prefix query — valid even for not-yet-allocated addresses.
    assert_eq!(
        m3.effective_owner(&a(&[1, 0, 2])),
        Some(BOOTSTRAP_PRINCIPAL)
    );
    assert_eq!(m3.effective_owner(&a(&[1, 0, 1, 0, 9, 0, 1, 5])), Some(ID1));
    // Uncovered (a foreign node's subtree): None.
    assert!(m3.effective_owner(&a(&[2])).is_none());
    assert!(m3.effective_owner(&a(&[2, 0, 1])).is_none());

    // The authorization predicate agrees with ω everywhere, and is where the
    // divergence bites: π₀ CONTAINS the account but is not its ω, so
    // containment says yes exactly where authorization says no.
    assert!(m3.is_effective_owner(ID1, &doc));
    assert!(m3.is_effective_owner(ID1, &acct));
    assert!(prefix_contains(&a(&[1]), &acct));
    assert!(!m3.is_effective_owner(BOOTSTRAP_PRINCIPAL, &acct));
    assert!(m3.is_effective_owner(BOOTSTRAP_PRINCIPAL, &a(&[1])));
    // An unknown id owns nothing; an uncovered address has no owner at all,
    // and absent-ω is not-owner rather than a pass.
    assert!(!m3.is_effective_owner(UNKNOWN_ID, &doc));
    assert!(!m3.is_effective_owner(ID1, &a(&[2, 0, 1])));
    assert!(!m3.is_effective_owner(BOOTSTRAP_PRINCIPAL, &a(&[2, 0, 1])));
}

#[test]
fn omega_is_the_longest_covering_prefix_at_every_depth() {
    // §5 / O2/O3: ω is the LONGEST principal prefix, and is_effective_owner
    // agrees with it everywhere. Checked against an independent oracle — the
    // linear scan keeping the longest match, which the design names as the
    // reference — over a GENERATED family of probes, so no chosen point
    // decides it and a candidate walk that truncates at depth is caught.
    let seeded = World {
        m3: M3State::genesis()
            .apply_m3(&alloc(&[1, 0, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 1]),
                id: ID1,
            })
            .apply_m3(&alloc(&[1, 0, 1, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 1, 1]),
                id: ID2,
            })
            .apply_m3(&alloc(&[1, 0, 1, 1, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 1, 1, 1]),
                id: PrincipalId(3),
            })
            .apply_m3(&alloc(&[1, 0, 2]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 2]),
                id: PrincipalId(4),
            }),
    };
    let pi = [
        (a(&[1]), BOOTSTRAP_PRINCIPAL),
        (a(&[1, 0, 1]), ID1),
        (a(&[1, 0, 1, 1]), ID2),
        (a(&[1, 0, 1, 1, 1]), PrincipalId(3)),
        (a(&[1, 0, 2]), PrincipalId(4)),
    ];
    // Independent oracle: reconstruct x's OWN node/account-tier prefixes,
    // longest first, and take the first that names a principal. That is the
    // other derivation of ω — deliberately not the implementation's, which
    // walks Π and keeps the longest cover — so the two can only agree by
    // both being right.
    let oracle = |x: &Address| -> Option<PrincipalId> {
        (1..=x.tumbler().len()).rev().find_map(|plen| {
            let p = validate(Tumbler::new(x.tumbler().iter().take(plen).cloned()).ok()?).ok()?;
            if !matches!(p.level(), Level::Node | Level::Account) {
                return None;
            }
            pi.iter().find(|(q, _)| *q == p).map(|(_, id)| *id)
        })
    };
    let m3 = seeded.m3;

    // The family: every prefix of a deep address, each of those with its
    // last component bumped (an uncovered sibling), and a foreign node's
    // subtree.
    let deep = [1u32, 0, 1, 1, 1, 0, 1, 0, 1, 1];
    let mut probes = vec![
        a(&[2]),
        a(&[2, 0, 1]),
        a(&[1, 0, 3]),
        a(&[1, 0, 1, 2, 0, 1]),
    ];
    for len in 1..=deep.len() {
        if let Ok(p) = validate(t(&deep[..len])) {
            probes.push(p);
        }
        let mut bumped = deep[..len].to_vec();
        if let Some(last) = bumped.last_mut() {
            *last += 1;
        }
        if let Ok(p) = validate(t(&bumped)) {
            probes.push(p);
        }
    }
    assert!(
        probes.len() > 12,
        "the generated family is the point of this test"
    );

    let mut ids: Vec<PrincipalId> = pi.iter().map(|(_, id)| *id).collect();
    ids.push(UNKNOWN_ID);
    for x in &probes {
        assert_eq!(m3.effective_owner(x), oracle(x), "ω disagrees at {x:?}");
        for id in &ids {
            assert_eq!(
                m3.is_effective_owner(*id, x),
                oracle(x) == Some(*id),
                "is_effective_owner({id:?}, {x:?}) disagrees with ω"
            );
        }
    }
}

#[test]
fn omega_cost_does_not_follow_the_probes_depth() {
    // §5 cost discipline: ω's work is sized by Π, never by the address the
    // caller hands in. T4 constrains an address's zero pattern, NOT its
    // component count, so a ~100 KB dotted-decimal request can carry a
    // 50_000-component account-tier probe — and every prefix of it past the
    // separator is itself account-tier, so a per-candidate prefix walk has no
    // short-circuit and rebuilds ~1.25e9 components for this one call, while
    // `create_new_document` and `delegate` hold the global principals key
    // across exactly this read. Answering here in the same time as a
    // three-component probe is the refusal. Corpus seed for the fuzzing tier.
    let (k, _acct, _doc) = kernel_with_account_and_doc(); // Π = { [1]→π₀, [1,0,1]→ID1 }
    let snap = k.snapshot();
    let m3 = snap.world().m3();

    let mut deep = vec![1u32, 0];
    deep.extend(std::iter::repeat_n(1u32, 49_998));
    let deep = a(&deep);
    assert_eq!(deep.level(), Level::Account); // every prefix past [1,0] is a candidate
    assert_eq!(m3.effective_owner(&deep), Some(ID1));
    assert!(m3.is_effective_owner(ID1, &deep));
    assert!(!m3.is_effective_owner(BOOTSTRAP_PRINCIPAL, &deep));

    // Equally deep, under no principal at all: None, at the same cost.
    let mut foreign = vec![2u32, 0];
    foreign.extend(std::iter::repeat_n(1u32, 49_998));
    assert!(m3.effective_owner(&a(&foreign)).is_none());
}

// ---- §B delegate ----

#[test]
fn delegate_mints_account_and_principal_atomically() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);

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
    assert_eq!(m3.principal_prefix(ID1), Some(&acct));
    // Effective ownership moved to the new principal (O7).
    assert_eq!(m3.effective_owner(&acct), Some(ID1));
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
    assert_eq!(m3.effective_owner(&sub_acct), Some(ID2));
    // ω still refines by longest match beside the sub-account.
    assert_eq!(m3.effective_owner(&a(&[1, 0, 1, 2])), Some(ID1));

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
    let ns = Namespace::new(&k);

    // Pre-work rejections (§6, no transaction opened) win over every
    // in-closure condition — here the delegator is ALSO unknown:
    // NotValid (validate-lift; [1,0] has a trailing zero)…
    assert_eq!(
        rejected(ns.delegate(UNKNOWN_ID, t(&[1, 0]), ID1)),
        DelegateError::NotValid
    );
    // …then NotAccountTier (hoisted (iii)): a bare node prefix is T4-VALID
    // but parentless — the hoist must reject it typed, before any
    // namespace_of/lock-key construction (no panic), and a document-tier
    // prefix is equally out (zeros == 1, narrowed from O15's ≤ 1).
    assert_eq!(
        rejected(ns.delegate(UNKNOWN_ID, t(&[2]), ID1)),
        DelegateError::NotAccountTier
    );
    assert_eq!(
        rejected(ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1, 0, 1]), ID1)),
        DelegateError::NotAccountTier
    );
    // DelegatorUnknown: the first in-closure gate.
    assert_eq!(
        rejected(ns.delegate(UNKNOWN_ID, t(&[1, 0, 1]), ID1)),
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
    // (ii) precedes (iv): with ID1 above [1,0,1,1] and ID2 strictly under
    // it, a non-ω delegator earns NotAuthorized though top-down also
    // fails… ([1,0,1,1] is deliberately NOT itself a principal, since the
    // §6 (iv) single probe answers false when it is.)
    let seeded = World {
        m3: M3State::genesis()
            .apply_m3(&alloc(&[1, 0, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 1]),
                id: ID1,
            })
            .apply_m3(&alloc(&[1, 0, 1, 1]))
            .apply_m3(&alloc(&[1, 0, 1, 1, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 1, 1, 1]),
                id: ID2,
            }),
    };
    let flanked_k = mem_kernel(seeded);
    let flanked_ns = Namespace::new(&flanked_k);
    assert_eq!(
        rejected(flanked_ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1, 1]), PrincipalId(7))),
        DelegateError::NotAuthorized
    );
    // …while ω itself reaches (iv) — so delegation can never seat a
    // principal ABOVE an existing one (top-down nesting, O15 iv).
    assert_eq!(
        rejected(flanked_ns.delegate(ID1, t(&[1, 0, 1, 1]), PrincipalId(7))),
        DelegateError::NotTopDown
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
    assert!(snap.world().m3().principal_prefix(ID2).is_none());

    // ParentNotRegistered (P8, Conflicts §5) — on a FRESH kernel π₀ is ω of
    // [1,0,1,1] and that chain's next-form is satisfied, so the unregistered
    // parent is the only failing gate; with [1,0,1,2] it also precedes
    // NotNextForm.
    let fresh_k = mem_kernel(genesis_world());
    let fresh_ns = Namespace::new(&fresh_k);
    assert_eq!(
        rejected(fresh_ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1, 1]), ID2)),
        DelegateError::ParentNotRegistered
    );
    assert_eq!(
        rejected(fresh_ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1, 2]), ID2)),
        DelegateError::ParentNotRegistered
    );
    // id-freshness guards the bootstrap id too: no later principal may
    // re-claim id 0 (§7).
    assert_eq!(
        rejected(fresh_ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), BOOTSTRAP_PRINCIPAL)),
        DelegateError::DuplicateId
    );
    // DuplicateId precedes ParentNotRegistered: the id is taken AND [1,0,1]
    // — the parent of [1,0,1,1] — was never registered.
    assert_eq!(
        rejected(fresh_ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1, 1]), BOOTSTRAP_PRINCIPAL)),
        DelegateError::DuplicateId
    );

    // NotFresh and NotTopDown need an allocated-but-principal-less account;
    // the fold admits exactly the record shapes delegate itself stages
    // (apply_m3 totality domain), so seed one directly.
    let seeded = World {
        m3: M3State::genesis().apply_m3(&alloc(&[1, 0, 1])),
    };
    let allocated_k = mem_kernel(seeded);
    let allocated_ns = Namespace::new(&allocated_k);
    // (v) freshness: [1,0,1] is allocated (ω = π₀, so (ii) passes).
    assert_eq!(
        rejected(allocated_ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID2)),
        DelegateError::NotFresh
    );
    // NotFresh precedes DuplicateId: [1,0,1] is allocated AND id 0 is taken.
    assert_eq!(
        rejected(allocated_ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), BOOTSTRAP_PRINCIPAL)),
        DelegateError::NotFresh
    );
    // (iv) top-down: with a principal strictly under [1,0,1] the same call
    // rejects NotTopDown — which precedes NotFresh (the input violates
    // both).
    let seeded = World {
        m3: M3State::genesis()
            .apply_m3(&alloc(&[1, 0, 1]))
            .apply_m3(&alloc(&[1, 0, 1, 1]))
            .apply_m3(&M3Rec::RegisterPrincipal {
                prefix: a(&[1, 0, 1, 1]),
                id: ID2,
            }),
    };
    let nested_k = mem_kernel(seeded);
    let nested_ns = Namespace::new(&nested_k);
    assert_eq!(
        rejected(nested_ns.delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), PrincipalId(7))),
        DelegateError::NotTopDown
    );
}

// ---- §B create_new_document ----

#[test]
fn create_new_document_authorizes_by_omega() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
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

    // The ownership-divergence trap (O5): π₀'s prefix CONTAINS the account,
    // yet ω names ID1 — bare containment must not authorize.
    let before = k.current_seq();
    assert!(prefix_contains(&a(&[1]), &acct));
    assert_eq!(
        rejected(ns.create_new_document(BOOTSTRAP_PRINCIPAL, &acct)),
        CreateDocumentError::NotOwner
    );
    // An unknown caller is the effective owner of nothing.
    assert_eq!(
        rejected(ns.create_new_document(UNKNOWN_ID, &acct)),
        CreateDocumentError::NotOwner
    );
    // ω-auth is evaluated FIRST (§7): a non-owner of an unregistered
    // account gets NotOwner, while the owner (π₀ covers all unregistered
    // prefixes under [1]) reaches the structural mint gate — NotAnAccount
    // covers unregistered and node-tier targets alike.
    assert_eq!(
        rejected(ns.create_new_document(ID1, &a(&[1, 0, 2]))),
        CreateDocumentError::NotOwner
    );
    assert_eq!(
        rejected(ns.create_new_document(BOOTSTRAP_PRINCIPAL, &a(&[1, 0, 2]))),
        CreateDocumentError::Mint(MintError::NotAnAccount)
    );
    assert_eq!(
        rejected(ns.create_new_document(BOOTSTRAP_PRINCIPAL, &a(&[1]))),
        CreateDocumentError::Mint(MintError::NotAnAccount)
    );
    // A refused creation baptizes nothing: no commit, and the account's
    // document chain still stands where d1 and d2 left it — the next
    // creation takes ordinal 3, so no refusal spent a slot.
    assert_eq!(k.current_seq(), before);
    let (d3, _) = ns.create_new_document(ID1, &acct).expect("create 3");
    assert_eq!(d3, a(&[1, 0, 1, 0, 3]));
}

// ---- §B fork ----

#[test]
fn fork_mints_in_the_callers_own_account() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let (acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("delegate");

    // O10, account-tier: reduces to create_new_document(caller,
    // pfx(caller)) — a fresh self-owned document one tier below the prefix.
    let (d1, _) = ns.fork(ID1).expect("fork");
    assert_eq!(d1, a(&[1, 0, 1, 0, 1]));
    assert!(prefix_contains(&acct, &d1));
    let snap = k.snapshot();
    assert!(snap.world().m3().is_registered_document(&d1));
    assert!(snap.world().m3().is_effective_owner(ID1, &d1));
    // Shares the (account, 2) chain with create_new_document.
    let (d2, _) = ns.create_new_document(ID1, &acct).expect("create");
    assert_eq!(d2, a(&[1, 0, 1, 0, 2]));

    // Unknown id: typed NotOwner (an unregistered caller owns nothing).
    assert_eq!(
        rejected(ns.fork(UNKNOWN_ID)),
        CreateDocumentError::NotOwner
    );
    // Node-tier caller (π₀ at [1]): the node-tier O10 case is DROPPED —
    // typed Mint(NotAnAccount), never a silent skip (Conflicts §6).
    assert_eq!(
        rejected(ns.fork(BOOTSTRAP_PRINCIPAL)),
        CreateDocumentError::Mint(MintError::NotAnAccount)
    );
}

// ---- §B register_node ----

#[test]
fn register_node_validates_and_admits_supplied_addresses() {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);

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
    assert_eq!(m3.effective_owner(&n), Some(BOOTSTRAP_PRINCIPAL));
    // …and delegation beneath it works through the ordinary gate.
    let peek = m3.next_account_prefix(&n).expect("peek under new node");
    assert_eq!(peek, a(&[1, 7, 0, 1]));
    ns.delegate(BOOTSTRAP_PRINCIPAL, peek.tumbler().clone(), ID1)
        .expect("delegate under the new node");

    // Rejections, in the documented guard order. The first three are pure
    // pre-work (validity, level and depth read the address alone), the last
    // two read the registry under the held key.
    let before = k.current_seq();
    // NotValid — not T4 ([1,0] has a trailing zero).
    assert_eq!(rejected(ns.register_node(t(&[1, 0]))), NodeError::NotValid);
    // NotNode — account-level input; checked before lineage ([2,0,1] is
    // also not bootstrap-descended).
    assert_eq!(rejected(ns.register_node(t(&[2, 0, 1]))), NodeError::NotNode);
    // NotNode precedes NotFresh: [1,7,0,1] is account-level AND registered
    // (the delegation above allocated it).
    assert_eq!(
        rejected(ns.register_node(t(&[1, 7, 0, 1]))),
        NodeError::NotNode
    );
    // TooDeep — `nodes` is the ONE registry the frontier cannot compress, so
    // an entry's SIZE is refused rather than stored. The probe is otherwise
    // impeccable — node-level, fresh, bootstrap-descended — so depth is the
    // only guard that can be refusing it.
    let too_deep: Vec<u32> = std::iter::repeat_n(1u32, MAX_NODE_COMPONENTS + 1).collect();
    assert_eq!(a(&too_deep).level(), Level::Node);
    assert_eq!(rejected(ns.register_node(t(&too_deep))), NodeError::TooDeep);
    // NotNode precedes TooDeep: an equally over-long ACCOUNT-tier address is
    // refused for its tier, since depth bounds the node registry alone.
    let mut deep_acct = vec![1u32, 0];
    deep_acct.extend(std::iter::repeat_n(1u32, MAX_NODE_COMPONENTS + 1));
    assert_eq!(rejected(ns.register_node(t(&deep_acct))), NodeError::NotNode);
    // NotFresh — duplicates surface typed, never a silent coalesce; the
    // seeded [1] and the just-registered [1,7] alike.
    assert_eq!(rejected(ns.register_node(t(&[1]))), NodeError::NotFresh);
    assert_eq!(rejected(ns.register_node(t(&[1, 7]))), NodeError::NotFresh);
    // NotDescendantOfBootstrap — [1] ≼ addr fails.
    assert_eq!(
        rejected(ns.register_node(t(&[2]))),
        NodeError::NotDescendantOfBootstrap
    );
    // A rejected admission commits nothing, whichever guard refused it.
    assert_eq!(k.current_seq(), before);

    // The cap is exactly where it says it is: one component shorter than the
    // refusal above is admitted, so `TooDeep` bounds the registry rather than
    // narrowing what provisioning may name.
    let at_cap: Vec<u32> = std::iter::repeat_n(1u32, MAX_NODE_COMPONENTS).collect();
    assert_eq!(
        ns.register_node(t(&at_cap)).expect("at the cap").0,
        a(&at_cap)
    );
    assert_eq!(
        k.snapshot().world().m3().entity_level(&a(&at_cap)),
        Some(Level::Node)
    );

    // NotFresh precedes NotDescendantOfBootstrap: [2] is registered AND off
    // the bootstrap lineage — a state `register_node` itself cannot reach,
    // so seed it through the fold.
    let seeded = World {
        m3: M3State::genesis().apply_m3(&M3Rec::RegisterNode { addr: a(&[2]) }),
    };
    let k2 = mem_kernel(seeded);
    assert_eq!(
        rejected(Namespace::new(&k2).register_node(t(&[2]))),
        NodeError::NotFresh
    );
}

#[test]
fn pre_work_rejections_open_no_transaction() {
    // §6/§7: `delegate`'s NotValid/NotAccountTier, `register_node`'s
    // NotValid/NotNode/TooDeep and `fork`'s unknown id are decided from the
    // argument alone and reject with NO transaction opened. M2 answers a
    // nested `transact` with a panic naming the broken obligation and permits
    // `snapshot()` inside a closure (kernel §3), so calling them from inside
    // a transaction is what separates "rejected before opening one" from
    // "rejected inside one" — `current_seq` cannot, since a rejected closure
    // draws no Seq either. `TooDeep` is here for the reason it exists: an
    // oversized admission must cost nothing, not a lock and a transaction.
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let too_deep: Vec<u32> = std::iter::repeat_n(1u32, MAX_NODE_COMPONENTS + 1).collect();
    k.transact::<_, ()>(&[], |_stg| {
        assert_eq!(
            rejected(ns.delegate(ID1, t(&[1, 0]), ID2)),
            DelegateError::NotValid
        );
        assert_eq!(
            rejected(ns.delegate(ID1, t(&[2]), ID2)),
            DelegateError::NotAccountTier
        );
        assert_eq!(rejected(ns.register_node(t(&[1, 0]))), NodeError::NotValid);
        assert_eq!(rejected(ns.register_node(t(&[2, 0, 1]))), NodeError::NotNode);
        assert_eq!(rejected(ns.register_node(t(&too_deep))), NodeError::TooDeep);
        assert_eq!(
            rejected(ns.fork(UNKNOWN_ID)),
            CreateDocumentError::NotOwner
        );
        Ok(())
    })
    .expect("the outer transaction is a zero-step commit");
}

// ---- the fold's totality domain ----

/// Outside `apply_m3`'s totality domain (§Core data model): the count
/// representation cannot hold a gap, so a jumped ordinal would make
/// [1,0,1]..[1,0,4] phantom entities (B1/B3). The guard is a `debug_assert`,
/// so this states the fail-stop only where debug assertions are compiled in.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "Allocate ordinal must equal its namespace frontier + 1")]
fn a_jumped_allocate_ordinal_fail_stops_the_fold() {
    let _ = M3State::genesis().apply_m3(&alloc(&[1, 0, 5]));
}

/// The same guard in the other direction: a re-staged Allocate would
/// silently regress the frontier and re-hand an address already minted.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "Allocate ordinal must equal its namespace frontier + 1")]
fn a_regressed_allocate_ordinal_fail_stops_the_fold() {
    let s = M3State::genesis()
        .apply_m3(&alloc(&[1, 0, 1]))
        .apply_m3(&alloc(&[1, 0, 2]));
    let _ = s.apply_m3(&alloc(&[1, 0, 1]));
}

// ---- serde / recovery ----

#[test]
fn journaled_types_survive_serde_round_trips() {
    // M3Rec — the journal delta — through M2's actual wire format (bincode).
    let recs = [
        M3Rec::Allocate { addr: a(&[1, 0, 1]) },
        M3Rec::RegisterNode { addr: a(&[1, 7]) },
        M3Rec::RegisterPrincipal {
            prefix: a(&[1, 0, 1]),
            id: ID1,
        },
    ];
    for rec in &recs {
        let bytes = bincode::serialize(rec).expect("serialize M3Rec");
        let back: M3Rec = bincode::deserialize(&bytes).expect("deserialize M3Rec");
        assert_eq!(*rec, back); // whole value: variant AND payload
    }

    // The Address payloads journal as bare, flat tumblers — the data model's
    // form, not the in-memory type's. A shadow record carrying Tumblers
    // encodes byte-identically, variant for variant.
    #[derive(Serialize)]
    enum TumblerRec {
        Allocate { addr: Tumbler },
        RegisterNode { addr: Tumbler },
        RegisterPrincipal { prefix: Tumbler, id: PrincipalId },
    }
    let shadows = [
        TumblerRec::Allocate { addr: t(&[1, 0, 1]) },
        TumblerRec::RegisterNode { addr: t(&[1, 7]) },
        TumblerRec::RegisterPrincipal {
            prefix: t(&[1, 0, 1]),
            id: ID1,
        },
    ];
    for (rec, shadow) in recs.iter().zip(&shadows) {
        assert_eq!(
            bincode::serialize(rec).expect("serialize M3Rec"),
            bincode::serialize(shadow).expect("serialize the tumbler shadow"),
        );
    }

    // A tumbler that is not T4-valid cannot arrive as a record: the payload
    // re-validates on the way off the journal (M1's validating Deserialize),
    // so the fold is never handed a malformed address.
    let malformed = bincode::serialize(&TumblerRec::RegisterNode { addr: t(&[1, 0]) })
        .expect("serialize the tumbler shadow");
    assert!(bincode::deserialize::<M3Rec>(&malformed).is_err());

    // Nor can a PARENTLESS Allocate. [7] is T4-valid, so M1's door passes it
    // — and `apply_m3` derives its namespace from the parent, which a
    // one-component node has none of, so folding one would panic the applier
    // at every replay from then on. M3's own door is what refuses it, before
    // the record is ever a value.
    for parentless in [t(&[7]), t(&[1])] {
        let frame = bincode::serialize(&TumblerRec::Allocate { addr: parentless })
            .expect("serialize the tumbler shadow");
        assert!(
            bincode::deserialize::<M3Rec>(&frame).is_err(),
            "a parentless Allocate decoded into a record"
        );
    }
    // The refusal is exactly the parentless case, not a length rule: the
    // shortest address that DOES extend a parent still decodes.
    let shortest = bincode::serialize(&TumblerRec::Allocate { addr: t(&[1, 1]) })
        .expect("serialize the tumbler shadow");
    assert_eq!(
        bincode::deserialize::<M3Rec>(&shortest).expect("a two-component Allocate decodes"),
        M3Rec::Allocate { addr: a(&[1, 1]) }
    );
    // …and RegisterNode is untouched by it: a one-component node is exactly
    // what that variant carries.
    let bare_node_frame = bincode::serialize(&TumblerRec::RegisterNode { addr: t(&[7]) })
        .expect("serialize the tumbler shadow");
    assert_eq!(
        bincode::deserialize::<M3Rec>(&bare_node_frame).expect("a bare node registers"),
        M3Rec::RegisterNode { addr: a(&[7]) }
    );

    // M3State — the checkpointed slice: every field is ordinary serde (none
    // skip-serialized; default rebuild_derived), so a round-tripped state
    // answers identically.
    let (k, acct, doc) = kernel_with_account_and_doc();
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
    assert_eq!(back.next_account_prefix(&a(&[1])), Some(a(&[1, 0, 2])));
    // The whole principal registry rides inside the slice — both its
    // entries, both directions (id → prefix, address → ω).
    assert_eq!(back.principal_prefix(ID1), Some(&acct));
    assert_eq!(back.effective_owner(&doc), Some(ID1));
    assert_eq!(back.principal_prefix(BOOTSTRAP_PRINCIPAL), Some(&a(&[1])));
    assert_eq!(back.effective_owner(&a(&[1])), Some(BOOTSTRAP_PRINCIPAL));
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
        let k = Arc::new(Kernel::open(fsync_config(dir.path()), genesis_world()).expect("open"));
        let ns = Namespace::new(&k);
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
    let k2 = Kernel::open(fsync_config(dir.path()), genesis_world()).expect("reopen");
    let snap = k2.snapshot();
    let m3 = snap.world().m3();
    assert_eq!(m3.principal_prefix(ID1), Some(&acct));
    assert!(m3.is_registered_document(&doc));
    assert_eq!(m3.entity_level(&a(&[1, 7])), Some(Level::Node));
    assert_eq!(m3.effective_owner(&doc), Some(ID1));
    // The frontiers recovered too: the chains continue where they left off.
    assert_eq!(m3.next_account_prefix(&a(&[1])), Some(a(&[1, 0, 2])));
    let (d2, _) = m3.mint_document(&acct).expect("mint after recovery");
    assert_eq!(d2, a(&[1, 0, 1, 0, 2]));
}
