//! §D genesis: Σ₀'s roots and the system-account seed folded onto them
//! (PUB-6.65), and the one value they make, byte for byte.

use crate::common::*;

use serde::Serialize;
use skep_address::{Level, Nat, Tumbler};
use skep_namespace::{
    ghost_home_document, head_document, staging_draft, system_account, system_node, time_document,
    M3State, PrincipalId, BOOTSTRAP_PRINCIPAL, SYSTEM_PRINCIPAL,
};

#[test]
fn genesis_seeds_the_bootstrap_roots_and_the_system_account() {
    // Σ₀ + O14 — the roots: node [1] and π₀ seated at it. Then the
    // system-account seed (PUB-6.65), seven records folded onto them: the
    // system node 1.1 admitted, the account 1.1.0.1 baptized and seated for
    // SYSTEM_PRINCIPAL, and its four documents: doc 1 (the commons
    // registry's future home), doc 2 (the head document H) and doc 4 (the
    // time document T) born PUBLISHED, and doc 3 (the staging draft) born
    // UNPUBLISHED. Each record has an assertion below that fails without it.
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
    // allocated AND seated — the two halves `delegate` stages; its four
    // documents registered, each with the bit it was born with, at their
    // fixed addresses, and nothing else in the map.
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
    let seeded = [
        (ghost_home_document(), a(&[1, 1, 0, 1, 0, 1]), true),
        (head_document(), a(&[1, 1, 0, 1, 0, 2]), true),
        (staging_draft(), a(&[1, 1, 0, 1, 0, 3]), false),
        (time_document(), a(&[1, 1, 0, 1, 0, 4]), true),
    ];
    for (doc, at, published) in &seeded {
        assert_eq!(doc, at, "{doc:?} stands at its fixed address");
        assert!(s.is_registered_document(doc), "{doc:?} is seeded");
        assert_eq!(s.published(doc), *published, "{doc:?} keeps the bit it was born with");
        assert_eq!(s.minted_at(doc), Some(Seq(0)), "{doc:?} is entered at the genesis coordinate");
    }
    assert_eq!(
        s.documents().collect::<Vec<_>>(),
        seeded.iter().map(|(doc, _, published)| (doc, *published)).collect::<Vec<_>>(),
        "the four seeded documents and no other, in address order"
    );
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
        a(&[1, 1, 0, 1, 0, 5]),
        "the seed's four documents stand, so the account's next mint is doc 5"
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
/// "seeds one unpublished document, the staging draft, and no link": the
/// publication suite pins the slice's three trailing fields as a suffix, and
/// a seeded link, content atom or chain count moves the frontier map alone.
/// That map's key is the crate's private `NsKey`, whose bytes are its anchor
/// tumbler and then its generator numeral (`ns/tests.rs` pins the shape), so
/// a raw struct of that shape spells its two entries: the system node's
/// account chain `(1.1, 2)` at 1, and the system account's document chain
/// `(1.1.0.1, 2)` at 4. Every value is spelled as the bytes it must be, the
/// two fixed ids included: a pin spelled by their constants would carry any
/// change to them along.
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
            Nat::from(4u32),
        ),
    ])
    .expect("the frontier map");
    let nodes = bincode::serialize(&vec![t(&[1]), t(&[1, 1])]).expect("the node set");
    // The two fixed ids by VALUE, never by the constants this pin watches: π₀
    // is id 0 (O14), and the system principal is the reserved sentinel
    // 9 × 10^15, below the wire's 2^53 − 1 (AUTH-5.20; PUB-6.65).
    let principals = bincode::serialize(&vec![
        (t(&[1]), PrincipalId(0)),
        (t(&[1, 1, 0, 1]), PrincipalId(9_000_000_000_000_000)),
    ])
    .expect("the principal map");
    // The publication map: the seed's four documents, the staging draft
    // alone born unpublished.
    let publication = bincode::serialize(&vec![
        (t(&[1, 1, 0, 1, 0, 1]), true),
        (t(&[1, 1, 0, 1, 0, 2]), true),
        (t(&[1, 1, 0, 1, 0, 3]), false),
        (t(&[1, 1, 0, 1, 0, 4]), true),
    ])
    .expect("the publication map");
    // The position map: the seed's four documents, minted at the genesis
    // coordinate, each entry an address and an eight-byte position.
    let minted_at = bincode::serialize(&vec![
        (t(&[1, 1, 0, 1, 0, 1]), 0u64),
        (t(&[1, 1, 0, 1, 0, 2]), 0u64),
        (t(&[1, 1, 0, 1, 0, 3]), 0u64),
        (t(&[1, 1, 0, 1, 0, 4]), 0u64),
    ])
    .expect("the position map");
    assert_eq!(
        bincode::serialize(&M3State::genesis()).expect("serialize genesis"),
        [frontiers, nodes, principals, publication, minted_at].concat(),
        "Σ₀ drifted: every journal replayed from genesis would fold onto another world"
    );
}
