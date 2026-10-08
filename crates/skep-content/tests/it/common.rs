//! The minimal engine assembly the suites run on, and the helpers they
//! share. The toy `World`/`Rec` pair is what the composition contract
//! prescribes: `HasContent` read accessor, `From<ContentWrite>` record lift,
//! `apply` dispatching into `ContentStore::apply_write`.

use std::path::Path;

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Tumbler};
use skep_content::{ContentStore, ContentWrite, HasContent, Val};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelConfig, SaltSource, TxnError,
    WorldState,
};

// ---- the minimal engine assembly (composition contract) ----

#[derive(Clone, Serialize, Deserialize)]
pub struct World {
    content: ContentStore,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Rec(ContentWrite);

impl From<ContentWrite> for Rec {
    fn from(r: ContentWrite) -> Rec {
        Rec(r)
    }
}

impl HasContent for World {
    fn content(&self) -> &ContentStore {
        &self.content
    }
}

impl WorldState for World {
    type Record = Rec;
    fn apply(&self, r: &Rec) -> World {
        World {
            content: self.content.apply_write(&r.0),
        }
    }
}

// ---- helpers ----
//
// A helper that checks what its caller handed it — a literal that must be
// a tumbler or a T4-valid address, an outcome that must be a rejection —
// is `#[track_caller]`, as the library's two write doors are, so its
// panic is reported at the test's line, never at this file's.

#[track_caller]
pub fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

#[track_caller]
pub fn a(comps: &[u32]) -> Address {
    validate(t(comps)).expect("test addresses are T4-valid")
}

/// A content element address in M3's minted shape: doc `[1,0,1,0,1]`,
/// element field `[s_C = 1, ordinal]`.
#[track_caller]
pub fn ca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 1, ordinal])
}

/// One T4-valid address of each shape the routing assertion stops in a debug
/// build — each level short of an element, and an element in a subspace other
/// than content's — with the name a failure reports it by. Two tests read it:
/// store.rs's release staging test stages each as given, and recovery.rs's
/// decode test admits each, so the shapes one door takes and the other admits
/// cannot part.
pub const MIS_ROUTED: &[(&str, &[u32])] = &[
    ("a node address", &[1]),
    ("an account address", &[1, 0, 1]),
    ("a document address", &[1, 0, 1, 0, 1]),
    ("a link-subspace element address", &[1, 0, 1, 0, 1, 0, 2, 1]),
    ("a subspace-3 element address", &[1, 0, 1, 0, 1, 0, 3, 1]),
];

pub fn val(b: &[u8]) -> Val {
    Val::new(b)
}

pub fn genesis() -> World {
    World {
        content: ContentStore::default(),
    }
}

pub fn mem_kernel() -> Kernel<World> {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    };
    Kernel::open(cfg, genesis()).expect("in-memory open")
}

pub fn cfg_fsync(dir: &Path) -> KernelConfig {
    KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 1,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    }
}

/// Unwrap an op's typed rejection (`TxnError::Rejected(E)` — surfaced
/// verbatim, per M2's transact contract).
#[track_caller]
pub fn rejected<T: std::fmt::Debug, E: std::fmt::Debug>(r: Result<T, TxnError<E>>) -> E {
    match r {
        Err(TxnError::Rejected(e)) => e,
        other => panic!("expected TxnError::Rejected, got {other:?}"),
    }
}
