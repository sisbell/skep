//! The unit tests' shared fixtures, compiled for the crate's own tests alone.
//!
//! They are the in-memory engine every in-crate suite but the canon's and the
//! types' stands up, the delegated account most of them start from, the
//! address constructors they spell addresses with, and the published home
//! beside a private draft that three of them deposit across.
//!
//! `tests/it/common` is this module's twin for the integration suite, and the
//! two cannot share: an integration test is a separate crate, which reaches
//! nothing compiled under `#[cfg(test)]` here, and a unit test cannot reach a
//! file under `tests/`. So each owns its own copy of one small prologue.
//!
//! What a fixture mints stays that fixture's own where its flags are what its
//! tests are about — a draft doc 1, say. The published home beside a later
//! draft is here because three suites mint exactly that pair, and each would
//! otherwise assert it afresh.

use skep_address::{validate, Address, Nat, Tumbler};
use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
use skep_namespace::{HasM3, PrincipalId, BOOTSTRAP_PRINCIPAL};

use crate::Engine;

/// The principal the fixtures delegate to and write as.
pub(crate) const USER: PrincipalId = PrincipalId(7);

/// Returns an engine over an in-memory kernel, with no journal.
///
/// [`crate::World::genesis`] is installed as the root exactly as built. The
/// salt source is the seeded one every fixture uses — consulted by nothing
/// here, since an in-memory kernel frames no marker to salt.
///
/// # Panics
///
/// Panics where the in-memory open refuses, which it cannot.
pub(crate) fn mem_engine() -> Engine {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    };
    Engine::open(cfg).expect("in-memory open cannot fail")
}

/// Returns the T4-valid address with the components `comps`.
///
/// # Panics
///
/// Panics where `comps` is empty or not T4-valid.
#[track_caller]
pub(crate) fn addr(comps: &[u32]) -> Address {
    let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty");
    validate(t).expect("test addresses are T4-valid")
}

/// Returns an element of `doc`'s subspace `s` at ordinal `n`, never minted.
///
/// Neither a link slot nor an `emit` member requires it minted. Subspace 1 is
/// a document's content space, so an element there is a position a
/// projection can name; subspace 3 is a space nothing ever mints into, so a
/// type slot filled from it lands in a coverage class of its own.
///
/// # Panics
///
/// Panics where `s` or `n` is zero, or where `doc` is an element, since the
/// address is then not T4-valid.
#[track_caller]
pub(crate) fn element(doc: &Address, s: u32, n: u32) -> Address {
    let comps =
        doc.tumbler().iter().cloned().chain([Nat::from(0u32), Nat::from(s), Nat::from(n)]);
    validate(Tumbler::new(comps).expect("nonempty")).expect("an element of a document is T4-valid")
}

/// Returns a fresh account under the genesis node `[1]`, delegated from π₀.
///
/// It is delegated to `principal` at the prefix M3 names next: peeked off one
/// snapshot and claimed by the next commit, which nothing else in a
/// single-threaded test can take first.
///
/// # Panics
///
/// Panics where the genesis node has no delegable next prefix, or where the
/// delegation is refused.
#[track_caller]
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

/// Returns an account's published home and private draft, with their engine.
///
/// The account is [`USER`]'s, and the engine is the in-memory one that
/// minted both: `(engine, home, draft)`. The account's first flagless mint is
/// its home (PUB-8.21) and a later one is a draft, and both states are
/// asserted here, so a suite that deposits across that boundary — the dump
/// filter's, the grant fold's, the hint check's — states only what it
/// deposits.
///
/// # Panics
///
/// Panics where a mint is refused, or where the home does not read published
/// or the draft does not read private.
#[track_caller]
pub(crate) fn a_published_home_and_a_private_draft() -> (Engine, Address, Address) {
    let engine = mem_engine();
    let acct = delegated_account(&engine, USER);
    let (home, _) =
        engine.namespace().create_new_document(USER, &acct, None).expect("the home mint");
    let (draft, _) = engine
        .namespace()
        .create_new_document(USER, &acct, None)
        .expect("a later mint, private");
    {
        let snap = engine.kernel().snapshot();
        let world = snap.world();
        assert!(world.readable(None, &home), "the first flagless mint is published");
        assert!(!world.readable(None, &draft), "a later flagless mint is a draft");
    }
    (engine, home, draft)
}
