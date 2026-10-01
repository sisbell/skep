//! §D genesis: Σ₀'s roots and the system-account seed folded onto them
//! (PUB-6.65).

use crate::common::*;

use skep_address::Level;
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
