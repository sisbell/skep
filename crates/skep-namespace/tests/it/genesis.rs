//! §D genesis: Σ₀'s roots and the system-account seed folded onto them
//! (PUB-6.65), and the one value they make, byte for byte.

use crate::common::*;

use serde::Serialize;
use skep_address::{Level, Nat, Tumbler};
use skep_namespace::{
    ghost_home_document, head_document, system_account, system_node, M3State, BOOTSTRAP_PRINCIPAL,
    SYSTEM_PRINCIPAL,
};

#[test]
fn genesis_seeds_the_bootstrap_roots_and_the_system_account() {
    // Σ₀ + O14 — the roots: node [1] and π₀ seated at it. Then the
    // system-account seed (PUB-6.65), five records folded onto them: the
    // system node 1.1 admitted, the account 1.1.0.1 baptized and seated for
    // SYSTEM_PRINCIPAL, and its doc 1 (the commons registry's future home)
    // and doc 2 (the head document H), both born PUBLISHED. Each record has
    // an assertion below that fails without it.
    let s = M3State::genesis();
    assert_eq!(s.entity_level(&a(&[1])), Some(Level::Node));
    assert!(s.is_allocated(&a(&[1])));
    // π₀ resolves in both directions: its id names the root prefix, and the
    // root address names it as ω.
    assert_eq!(s.principal_prefix(BOOTSTRAP_PRINCIPAL), Some(&a(&[1])));
    assert_eq!(s.effective_owner(&a(&[1])), Some(BOOTSTRAP_PRINCIPAL));
    // Node [1]'s own account chain is untouched: nothing under it is
    // allocated, and its first slot is the claim ceremony's to take.
    assert!(!s.is_allocated(&a(&[1, 0, 1])));
    assert_eq!(s.entity_level(&a(&[1, 0, 1])), None);
    assert_eq!(s.next_account_prefix(&a(&[1])), Some(a(&[1, 0, 1])));
    // The seed, in M3's own reads: the system node admitted; the account
    // allocated AND seated — the two halves `delegate` stages; its two
    // documents registered and born published, and nothing else in the map.
    assert_eq!(s.entity_level(&system_node()), Some(Level::Node));
    assert!(s.is_registered_account(&system_account()));
    assert_eq!(
        s.principal_prefix(SYSTEM_PRINCIPAL),
        Some(&system_account())
    );
    assert_eq!(
        s.effective_owner_prefix(&system_account()),
        Some(&system_account())
    );
    for doc in [ghost_home_document(), head_document()] {
        assert!(s.is_registered_document(&doc), "{doc:?} is seeded");
        assert!(s.published(&doc), "{doc:?} is born published");
    }
    assert_eq!(s.documents().len(), 2);
    // …on the chains the ops would have advanced: P8's shape, which the
    // fold's contiguity check does not see.
    assert_eq!(
        s.next_account_prefix(&system_node()),
        Some(a(&[1, 1, 0, 2]))
    );
    assert_eq!(
        s.mint_document(&system_account(), false)
            .expect("the system account mints")
            .0,
        a(&[1, 1, 0, 1, 0, 3])
    );
    // Unknown ids resolve to nothing (single-valued scan, §5).
    assert!(s.principal_prefix(ID1).is_none());
    assert!(!s.is_effective_owner(ID1, &a(&[1])));
}

/// Σ₀ is ONE value, pinned here byte for byte. M2's caller contract on
/// `Kernel::open`: genesis MUST be byte-identical on every open of a given
/// journal, because recovery folds journaled deltas onto it — a drifting
/// genesis silently mis-recovers, and M2 cannot check it. Determinism inside
/// one build is the engine's `two_geneses_are_byte_identical`; drift ACROSS
/// builds only a pin can see. The pin is also the one watch on genesis's
/// "seeds no unpublished document and no link": the publication suite pins
/// the slice's three trailing fields as a suffix, and a seeded link, content
/// atom or chain count moves the frontier map alone. That map's key is the
/// crate's private `NsKey`, whose bytes are its anchor tumbler and then its
/// generator numeral (`ns/tests.rs` pins the shape), so a raw struct of that
/// shape spells its two entries: the system node's account chain `(1.1, 2)`
/// at 1, and the system account's document chain `(1.1.0.1, 2)` at 2.
#[test]
fn genesis_is_the_roots_and_the_seed_byte_for_byte() {
    #[derive(Serialize)]
    struct RawNsKey {
        parent: Tumbler,
        g: u8,
    }
    let frontiers = bincode::serialize(&vec![
        (
            RawNsKey {
                parent: t(&[1, 1]),
                g: 2,
            },
            Nat::from(1u32),
        ),
        (
            RawNsKey {
                parent: t(&[1, 1, 0, 1]),
                g: 2,
            },
            Nat::from(2u32),
        ),
    ])
    .expect("the frontier map");
    let nodes = bincode::serialize(&vec![t(&[1]), t(&[1, 1])]).expect("the node set");
    let principals = bincode::serialize(&vec![
        (t(&[1]), BOOTSTRAP_PRINCIPAL),
        (t(&[1, 1, 0, 1]), SYSTEM_PRINCIPAL),
    ])
    .expect("the principal map");
    let publication = bincode::serialize(&vec![
        (t(&[1, 1, 0, 1, 0, 1]), true),
        (t(&[1, 1, 0, 1, 0, 2]), true),
    ])
    .expect("the publication map");
    assert_eq!(
        bincode::serialize(&M3State::genesis()).expect("serialize genesis"),
        [frontiers, nodes, principals, publication].concat(),
        "Σ₀ drifted: every journal replayed from genesis would fold onto another world"
    );
}
