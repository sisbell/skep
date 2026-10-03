//! THE DOC-1 ADDRESS, computed twice (AUTH-2.126, AUTH-2.127): the identity
//! fold's `skep_identity::doc_1_of` — address arithmetic, `inc(a, 2)` =
//! `a·0·1`, total over node- and account-level prefixes — and M3's
//! `skep_namespace::first_document_address`, the slot the daemon's doc-1
//! test reads (`auth/policy.rs`'s `homed_in_doc_one`), `None` unless its
//! operand is account-level. The fold's home pin and the daemon's must agree
//! on which document is an account's doc 1, and the two cannot share one
//! function — skep-identity depends on no M3 (AUTH-2.1) — so they agree by
//! value, held here, in the one crate that links both:
//!
//! * at every account-level address the property draws, nested accounts
//!   among them, the two answer the same address;
//! * at a node-level prefix they part, the known difference: `doc_1_of`
//!   answers the node's first ACCOUNT, and `first_document_address` answers
//!   `None`.

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use skep_address::{validate, Address, Level, Nat, Tumbler};
use skep_identity::doc_1_of;
use skep_namespace::first_document_address;

/// The address whose components are `comps`, T4-valid by the caller's
/// construction.
fn address(comps: &[u64]) -> Address {
    let comps = comps.iter().map(|&c| Nat::from(c));
    validate(Tumbler::new(comps).expect("a tumbler")).expect("an address")
}

/// An account-level address: a node field and an account field of one to
/// four positive components each, one zero between them — a field of more
/// than one component past the zero is a nested account (`1.1.0.3.1`).
/// Small components and the whole `u64` range both.
fn account() -> impl Strategy<Value = Address> {
    let field = || prop::collection::vec(prop_oneof![1u64..10, 1u64..], 1..=4);
    (field(), field()).prop_map(|(node, account)| {
        let comps: Vec<u64> = node.into_iter().chain([0]).chain(account).collect();
        address(&comps)
    })
}

fn config() -> ProptestConfig {
    ProptestConfig {
        // A failure seed persists to `doc_one.proptest-regressions` beside
        // this file, pinned by name as `properties.rs` pins its own: the
        // default resolves through this binary's `main.rs` to a file no run
        // replays.
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// AUTH-2.126 — at every account-level address the fold's arithmetic
    /// and M3's slot answer one doc 1.
    #[test]
    fn the_fold_and_m3_compute_one_doc_1_at_every_account(a in account()) {
        prop_assert_eq!(a.level(), Level::Account);
        let slot = first_document_address(&a).expect("an account anchors a document chain");
        prop_assert_eq!(doc_1_of(&a), slot);
    }
}

/// THE KNOWN DIFFERENCE — a node-level prefix, the root `1`, where genesis
/// seats the bootstrap principal: `doc_1_of` answers `1.0.1`, the node's
/// first ACCOUNT, and `first_document_address` answers `None`, since no node
/// anchors a document chain. The difference moves no verdict (AUTH-2.127):
/// the pin compares a home, which is a document, and `1.0.1` is none, so the
/// fold's pin and the daemon's doc-1 test both answer no there.
#[test]
fn at_a_node_doc_1_of_answers_and_first_document_address_does_not() {
    let node = address(&[1]);
    assert_eq!(node.level(), Level::Node);
    let answered = doc_1_of(&node);
    assert_eq!(answered, address(&[1, 0, 1]));
    assert_eq!(answered.level(), Level::Account, "the node's first account, no document");
    assert_eq!(first_document_address(&node), None);
}
