//! In-crate test fixtures.
//!
//! They include `mem_kernel_of`, which opens the in-memory kernel every
//! in-crate test world runs on, and `rejected`, which unwraps an op's typed
//! refusal. Addresses follow M3's minted shapes: account `[1,0,1]`, documents
//! `[1,0,1,0,d]`, content elements `[doc·0·s_C·k]` (length 8), the version
//! fork `doc·1` whose content elements are length 9 — the mixed-length
//! transclusion case the level-class discipline exists for.

use skep_address::{validate, Address, Nat, Span, Tumbler};
use skep_kernel::{
    CheckpointPolicy, Durability, Kernel, KernelConfig, SaltSource, TxnError, WorldState,
};
use skep_namespace::{M3Rec, M3State, PrincipalId};

use crate::run::Run;
use crate::vspace::{ordinal_vspan, VPos};

pub(crate) fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

pub(crate) fn a(comps: &[u32]) -> Address {
    validate(t(comps)).expect("test addresses are T4-valid")
}

pub(crate) fn n(x: u32) -> Nat {
    Nat::from(x)
}

/// Returns document 1, `[1,0,1,0,1]`.
pub(crate) fn doc1() -> Address {
    a(&[1, 0, 1, 0, 1])
}

/// Returns document 2, `[1,0,1,0,2]`.
pub(crate) fn doc2() -> Address {
    a(&[1, 0, 1, 0, 2])
}

/// Returns document 3, `[1,0,1,0,3]`: the account's published edition.
///
/// It is the target the version-chain refusals (PUB-2.11) key on.
pub(crate) fn pdoc() -> Address {
    a(&[1, 0, 1, 0, 3])
}

/// Returns the first version fork of doc1, on M3's `(d_src, 1)` chain.
///
/// It is `[1,0,1,0,1,1]`.
pub(crate) fn vdoc() -> Address {
    a(&[1, 0, 1, 0, 1, 1])
}

/// Returns doc1's content element at `ordinal` (length 8).
///
/// It is `[1,0,1,0,1,0,1,ordinal]`.
///
/// # Panics
///
/// Panics where `ordinal` is zero: no T4-valid address ends in a zero.
pub(crate) fn ca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 1, ordinal])
}

/// Returns pdoc's content element at `ordinal` (length 8).
///
/// It is `[1,0,1,0,3,0,1,ordinal]`.
///
/// # Panics
///
/// Panics where `ordinal` is zero: no T4-valid address ends in a zero.
pub(crate) fn pca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 3, 0, 1, ordinal])
}

/// Returns doc1's link element at `ordinal` (length 8).
///
/// It is `[1,0,1,0,1,0,2,ordinal]`.
///
/// # Panics
///
/// Panics where `ordinal` is zero: no T4-valid address ends in a zero.
pub(crate) fn la(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 2, ordinal])
}

/// Returns vdoc's content element at `ordinal` (length 9).
///
/// It is `[1,0,1,0,1,1,0,1,ordinal]` — a different level class than [`ca`].
///
/// # Panics
///
/// Panics where `ordinal` is zero: no T4-valid address ends in a zero.
pub(crate) fn vca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 1, 0, 1, ordinal])
}

/// Returns a `Run` built through its own door, `Run::new`.
///
/// A test builds runs as a foreign producer must, so the standing invariants
/// — a start that is a full element position `doc·0·subspace·ordinal`, a
/// width ≥ 1 — hold in a test process as in every other.
///
/// # Panics
///
/// Panics where `start` is not a full element position or `width` is zero.
pub(crate) fn run(start: &Address, width: u32) -> Run {
    Run::new(start.clone(), n(width))
        .expect("a test run starts at a full element position, width ≥ 1")
}

/// Returns an ordinal-level depth-2 V-span of `count` positions.
///
/// Its start is `[subspace, ordinal]` and its width `[0, count]`.
///
/// # Panics
///
/// Panics where `count` is zero: there is no zero-width span.
pub(crate) fn vspan(subspace: u32, ordinal: u32, count: u32) -> Span {
    ordinal_vspan(vp(subspace, ordinal), n(count)).expect("test spans name ≥ 1 position")
}

/// Returns a depth-2 V-position.
pub(crate) fn vp(subspace: u32, ordinal: u32) -> VPos {
    VPos {
        subspace: n(subspace),
        ordinal: n(ordinal),
    }
}

/// Returns an M3 slice of two principal-owned accounts and three documents.
///
/// The documents are registered, and the slice is built by folding exactly
/// the records M3's own `delegate` / `create_new_document` would stage:
/// account `[1,0,1]` → principal 1 (owns doc1, doc2, pdoc), account
/// `[1,0,2]` → principal 2. The publication bits: doc1 and doc2 are private
/// drafts — the working documents the edit ops admit (doc1 as an
/// explicit-`false` first mint, the state M3 produces below the daemon's
/// first-mint door, PUB-8.20 being the daemon's alone) — and pdoc
/// `[1,0,1,0,3]` is a published edition (an explicit `true`), the target the
/// version-chain model's in-place refusal keys on (PUB-2.11). An account's
/// `Allocate` carries no publication state.
pub(crate) fn seeded_m3() -> M3State {
    M3State::genesis()
        .apply_m3(&M3Rec::allocate(a(&[1, 0, 1]), false))
        .apply_m3(&M3Rec::register_principal(a(&[1, 0, 1]), PrincipalId(1)))
        .apply_m3(&M3Rec::allocate(a(&[1, 0, 2]), false))
        .apply_m3(&M3Rec::register_principal(a(&[1, 0, 2]), PrincipalId(2)))
        .apply_m3(&M3Rec::allocate(a(&[1, 0, 1, 0, 1]), false))
        .apply_m3(&M3Rec::allocate(a(&[1, 0, 1, 0, 2]), false))
        .apply_m3(&M3Rec::allocate(a(&[1, 0, 1, 0, 3]), true))
}

/// Returns an in-memory kernel over `world`.
///
/// Every in-crate test world opens one this way: no journal, manual
/// checkpoints, a fixed salt.
pub(crate) fn mem_kernel_of<W: WorldState>(world: W) -> Kernel<W> {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    };
    Kernel::open(cfg, world).expect("in-memory open")
}

/// Returns the typed rejection an op's result carries.
///
/// That is `TxnError::Rejected(E)`, surfaced verbatim, per M2's transact
/// contract.
///
/// # Panics
///
/// Panics where `r` is `Ok` or a `TxnError` other than `Rejected`.
pub(crate) fn rejected<T, E: std::fmt::Debug>(r: Result<T, TxnError<E>>) -> E {
    match r {
        Err(TxnError::Rejected(e)) => e,
        Err(other) => panic!("expected TxnError::Rejected, got {other:?}"),
        Ok(_) => panic!("expected TxnError::Rejected, got Ok"),
    }
}
