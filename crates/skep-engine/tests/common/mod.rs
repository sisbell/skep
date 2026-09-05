//! Shared fixtures for the engine's integration tests: address/span
//! constructors, kernel configurations, and the bootstrap→delegate→create
//! prologue every cross-store scenario starts from.

#![allow(dead_code)] // each integration test binary uses a subset

use std::path::Path;

use skep_address::{validate, Address, Nat, Span, Tumbler};
use skep_arrangement::{Caller, VPos, VSpec};
use skep_engine::Engine;
use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig};
use skep_namespace::{HasM3, PrincipalId, BOOTSTRAP_PRINCIPAL};
use skep_retrieval::{Delivery, DeliveryItem};

pub const USER: PrincipalId = PrincipalId(7);

/// [`USER`] as the stores' ω-gated caller (the ownership ruling,
/// 2026-08-16) — the owner of everything `setup_doc` creates.
pub const OWNER: Caller = Caller::Principal(USER);

pub fn tum(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

pub fn addr(comps: &[u32]) -> Address {
    validate(tum(comps)).unwrap_or_else(|_| panic!("test addresses are T4-valid"))
}

pub fn nat(x: u32) -> Nat {
    Nat::from(x)
}

/// The genesis bootstrap node `[1]`.
pub fn node1() -> Address {
    addr(&[1])
}

pub fn vp(subspace: u32, ordinal: u32) -> VPos {
    VPos { subspace: nat(subspace), ordinal: nat(ordinal) }
}

/// An ordinal-level depth-2 V-span `[subspace, ordinal] w [0, width]`.
pub fn vspan(subspace: u32, ordinal: u32, width: u32) -> Span {
    Span::new(tum(&[subspace, ordinal]), tum(&[0, width]))
        .unwrap_or_else(|_| panic!("well-formed test span"))
}

/// A content V-spec over `doc`'s content subspace.
pub fn vspec(doc: &Address, ordinal: u32, width: u32) -> VSpec {
    VSpec { source: doc.clone(), span: vspan(1, ordinal, width) }
}

pub fn mem_cfg() -> KernelConfig {
    KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
    }
}

pub fn fsync_cfg(path: &Path) -> KernelConfig {
    KernelConfig {
        durability: Durability::Fsync {
            journal_path: path.to_path_buf(),
            retain_checkpoints: 1,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
    }
}

pub fn mem_engine() -> Engine {
    Engine::open(mem_cfg()).expect("in-memory open cannot fail")
}

/// Bootstrap prologue, all through the real drivers: peek the next delegable
/// prefix under the genesis node, delegate it to [`USER`], create one
/// document in the new account. Returns `(account, document)`.
pub fn setup_doc(engine: &Engine) -> (Address, Address) {
    let prefix = {
        let snap = engine.kernel().snapshot();
        snap.world()
            .m3()
            .next_account_prefix(&node1())
            .expect("the genesis node has a delegable next-form prefix")
    };
    let (acct, _) = engine
        .namespace()
        .delegate(BOOTSTRAP_PRINCIPAL, prefix.tumbler().clone(), USER)
        .expect("delegation of the peeked next-form prefix succeeds");
    let (doc, _) = engine
        .namespace()
        .create_new_document(USER, &acct, None)
        .expect("the delegated owner may create a document");
    (acct, doc)
}

/// The delivered content bytes, in delivery order; panics on a `Ref` item.
pub fn delivered_bytes(d: &Delivery) -> Vec<Vec<u8>> {
    d.0.iter()
        .map(|item| match item {
            DeliveryItem::Content(v) => v.as_bytes().to_vec(),
            DeliveryItem::Ref(_) => panic!("expected a content item, got a link reference"),
        })
        .collect()
}
