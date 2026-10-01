//! The minimal engine assembly every suite runs on, and the helpers they
//! share. The toy `World`/`Rec` pair is what the composition contract
//! prescribes: `HasM3` read accessor, `From<M3Rec>` record lift, `apply`
//! dispatching into `M3State::apply_m3`.

use std::path::Path;

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Tumbler};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelConfig, LockKey, SaltSource,
    TxnError, WorldState,
};
use skep_namespace::{
    HasM3, M3Rec, M3State, MintError, Namespace, PrincipalId, BOOTSTRAP_PRINCIPAL,
};

// ---- the minimal engine assembly (composition contract) ----

#[derive(Clone, Serialize, Deserialize)]
pub struct World {
    pub m3: M3State,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Rec(M3Rec);

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

pub fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

pub fn a(comps: &[u32]) -> Address {
    validate(t(comps)).expect("test addresses are T4-valid")
}

/// An `Allocate` off the publication axis — an account, an element, or a
/// document whose bit the test at hand never reads — stamped `false`, the
/// value the non-document mints stamp themselves. A test ABOUT the bit builds
/// its record explicitly.
pub fn alloc(comps: &[u32]) -> M3Rec {
    M3Rec::Allocate {
        addr: a(comps),
        published: false,
    }
}

pub fn genesis_world() -> World {
    World {
        m3: M3State::genesis(),
    }
}

pub fn mem_kernel(genesis: World) -> Kernel<World> {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    };
    Kernel::open(cfg, genesis).expect("in-memory open")
}

pub fn fsync_config(dir: &Path) -> KernelConfig {
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
pub fn rejected<T: std::fmt::Debug, E: std::fmt::Debug>(r: Result<T, TxnError<E>>) -> E {
    match r {
        Err(TxnError::Rejected(e)) => e,
        other => panic!("expected TxnError::Rejected, got {other:?}"),
    }
}

/// Mint under the matching lock key, stage the returned record, commit — the
/// M5/M7-shaped composite in one line, so a test can say what a chain does
/// once its records actually reach the fold.
pub fn commit_mint(
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

pub const ID1: PrincipalId = PrincipalId(1);
pub const ID2: PrincipalId = PrincipalId(2);
/// An id no principal in any fixture carries — the caller every op must
/// refuse, the ω no address resolves to, and the fresh `new_id` for a
/// delegation that must fail on a gate ahead of `DuplicateId`, where all that
/// matters is that the id is unseated.
pub const UNKNOWN_ID: PrincipalId = PrincipalId(99);

/// The standard fixture: genesis, then `delegate [1,0,1] → ID1`, then a
/// flagless `create_new_document` under it (⇒ doc `[1,0,1,0,1]`, the
/// account's doc 1, born PUBLISHED by the create-path default). The handle
/// borrows the kernel, so it stays inside; a test that needs one builds it
/// off the returned kernel.
pub fn kernel_with_account_and_doc() -> (Kernel<World>, Address, Address) {
    let k = mem_kernel(genesis_world());
    let ns = Namespace::new(&k);
    let (acct, _) = ns
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("bootstrap delegates the first account");
    let (doc, _) = ns
        .create_new_document(ID1, &acct, None)
        .expect("the delegate creates a document");
    (k, acct, doc)
}
