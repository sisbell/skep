//! The minimal engine assembly every suite runs on, and the helpers they
//! share. The toy `World`/`Rec` pair is what the composition contract
//! prescribes: `HasM3` read accessor, `From<M3Rec>` record lift, `apply`
//! dispatching into `M3State::apply_m3`.

use std::path::Path;

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Tumbler};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelConfig, LockKey, Reclaim,
    SaltSource, TxnError, WorldState,
};
use skep_namespace::{
    HasM3, M3Rec, M3State, MintError, Namespace, PrincipalId, BOOTSTRAP_PRINCIPAL,
    FIRST_ORDINARY_DOCUMENT,
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
    fn apply(&self, at: Seq, r: &Rec) -> World {
        World {
            m3: self.m3.apply_m3(at, &r.0),
        }
    }
}

// The position the fold is handed, re-exported so every suite that seeds a
// slice through the fold spells it off `common`.
pub use skep_kernel::Seq;

// ---- helpers ----

pub fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

pub fn a(comps: &[u32]) -> Address {
    validate(t(comps)).expect("test addresses are T4-valid")
}

/// The address `tail` spells under `base`: `base`'s components, then
/// `tail`'s — a version of a document, an element of it, a document of an
/// account.
pub fn under(base: &Address, tail: &[u32]) -> Address {
    let comps = base.tumbler().iter().cloned().chain(tail.iter().map(|&c| Nat::from(c)));
    validate(Tumbler::new(comps).expect("test tumblers are nonempty"))
        .expect("test addresses are T4-valid")
}

/// `account`'s `k`-th document, its doc 1 first: the address its counter
/// hands out `k`-th. That is doc 1, and then the numbers from
/// `FIRST_ORDINARY_DOCUMENT` on, past the reserved block of well-known slots.
/// Every row of this suite that names a document a mint handed out after
/// doc 1, or the slot the next mint fills, is worked out here from the
/// constant, so none spells that number.
pub fn nth_document(account: &Address, k: u32) -> Address {
    assert!(k >= 1, "an account's documents are counted from its doc 1");
    let number = if k == 1 { 1 } else { FIRST_ORDINARY_DOCUMENT + k - 2 };
    under(account, &[0, number])
}

/// The named slots of an account's reserved block, by document number: the
/// well-known slots a record may fill, once each.
pub const NAMED_SLOTS: [u32; 4] = [2, 3, 4, 5];

/// The system account's slots genesis seeds, by document number: its head
/// document, its staging draft and its time document. Its slot 5 is named
/// and holds nothing.
pub const SEEDED_SYSTEM_SLOTS: [u32; 3] = [2, 3, 4];

/// The document at `account`'s slot `number`, a document number of its
/// reserved block: an address that names the slot whether or not anything
/// stands there.
pub fn slot(account: &Address, number: u32) -> Address {
    assert!(
        (2..FIRST_ORDINARY_DOCUMENT).contains(&number),
        "a slot is a document number of the reserved block"
    );
    under(account, &[0, number])
}

/// An `Allocate` off the publication axis — an account, an element, or a
/// document whose bit the test at hand never reads — stamped `false`, the
/// value the non-document mints stamp themselves. A test ABOUT the bit builds
/// its record explicitly.
pub fn alloc(comps: &[u32]) -> M3Rec {
    M3Rec::allocate(a(comps), false)
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
            reclaim: Reclaim::BelowOldestRetained,
            burned_seq: BurnedSeqPolicy::Rollback,
            cut_damaged_tail: false,
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
/// account's doc 1, born PUBLISHED by the create-path default, with the
/// account's mailbox `[1,0,1,0,2]` created in the same commit). The handle
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

/// The standard fixture's account holding its doc 1 and NO mailbox: genesis,
/// `delegate [1,0,1] → ID1`, then doc `[1,0,1,0,1]` minted published through
/// the pure mint in a composite of its own.
///
/// The create path's first mint creates the account's mailbox in its commit,
/// so this is the one way to an account whose count stands at 1 with slot 2
/// empty: a state the store admits and the daemon's door refuses
/// (`mint_home_first` keeps every mint but the create off an empty
/// account). The slot op's own cells read it, to place a slot's first
/// document under a count of 1 and past the block.
pub fn kernel_with_account_doc_1_and_no_mailbox() -> (Kernel<World>, Address, Address) {
    let k = mem_kernel(genesis_world());
    let (acct, _) = Namespace::new(&k)
        .delegate(BOOTSTRAP_PRINCIPAL, t(&[1, 0, 1]), ID1)
        .expect("bootstrap delegates the first account");
    let doc = commit_mint(&k, M3State::document_lock_key(&acct), |m3| m3.mint_document(&acct, true));
    let m3 = k.snapshot().world().m3().clone();
    assert!(m3.has_documents(&acct), "the premise: the account holds its doc 1");
    assert!(
        !m3.is_registered_document(&slot(&acct, 2)),
        "the premise: no mailbox stands — only a first create makes one"
    );
    (k, acct, doc)
}
