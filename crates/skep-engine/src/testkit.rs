//! The unit tests' shared fixtures: the in-memory engine every in-crate suite
//! stands up, the delegated account most of them start from, and the address
//! constructors they spell addresses with. Compiled for the crate's own tests
//! alone.
//!
//! `tests/it/common` is this module's twin for the integration suite, and the
//! two cannot share: an integration test is a separate crate, which reaches
//! nothing compiled under `#[cfg(test)]` here, and a unit test cannot reach a
//! file under `tests/`. So each owns its own copy of one small prologue.
//!
//! What a fixture MINTS stays that fixture's own — a draft doc 1, or a
//! published home beside a later draft — because the flags it mints with are
//! what its tests are about. What every fixture does before minting is here.

// The dump's suites are the only callers of some of these, and they are
// compiled with the `dump` feature alone.
#![allow(dead_code)]

use skep_address::{validate, Address, Nat, Tumbler};
use skep_kernel::{CheckpointPolicy, Durability, KernelConfig};
use skep_namespace::{HasM3, PrincipalId, BOOTSTRAP_PRINCIPAL};

use crate::Engine;

/// The principal the fixtures delegate to and write as.
pub(crate) const USER: PrincipalId = PrincipalId(7);

/// An engine over an in-memory kernel: no journal, and [`crate::World::genesis`]
/// installed as the root exactly as built.
pub(crate) fn mem_engine() -> Engine {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
    };
    Engine::open(cfg).expect("in-memory open cannot fail")
}

/// A T4-valid address from its components.
pub(crate) fn addr(comps: &[u32]) -> Address {
    let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c)))
        .unwrap_or_else(|_| panic!("test tumblers are nonempty"));
    validate(t).unwrap_or_else(|_| panic!("test addresses are T4-valid"))
}

/// An element of `doc`'s subspace `s` at ordinal `n` — NEVER MINTED, which
/// neither a link slot nor an `emit` member requires. Subspace 1 is a
/// document's content space, so an element there is a position a projection
/// can name; subspace 3 is a space nothing ever mints into, so a type slot
/// filled from it lands in a coverage class of its own.
pub(crate) fn element(doc: &Address, s: u32, n: u32) -> Address {
    let comps =
        doc.tumbler().iter().cloned().chain([Nat::from(0u32), Nat::from(s), Nat::from(n)]);
    validate(Tumbler::new(comps).expect("nonempty")).expect("an element of a document is T4-valid")
}

/// A fresh ACCOUNT under the genesis node `[1]`, delegated from π₀ to
/// `principal` at the prefix M3 names next: peeked off one snapshot and
/// claimed by the next commit, which nothing else in a single-threaded test
/// can take first.
pub(crate) fn delegated_account(engine: &Engine, principal: PrincipalId) -> Address {
    let prefix = engine
        .kernel()
        .snapshot()
        .world()
        .m3()
        .next_account_prefix(&addr(&[1]))
        .expect("the genesis node has a delegable next-form prefix");
    let (account, _) = engine
        .namespace()
        .delegate(BOOTSTRAP_PRINCIPAL, prefix.tumbler().clone(), principal)
        .expect("delegation of the peeked prefix succeeds");
    account
}
