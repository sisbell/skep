//! §D genesis: what Σ₀ seeds, and the seeded slice as a reader prints it.

use crate::common::*;

use skep_address::Level;
use skep_namespace::{HasM3, M3State, BOOTSTRAP_PRINCIPAL};

#[test]
fn genesis_seeds_bootstrap_node_and_principal() {
    // Σ₀ + O14, as seeded since the published head (PUB-6.65, 2026-09-23):
    // nodes = {[1], [1.1]}; Π = {[1] → π₀, [1.1.0.1] → SYSTEM_PRINCIPAL};
    // frontiers = {([1.1], 2) → 1, ([1.1.0.1], 2) → 2} — the system node's
    // account chain and the system account's document chain, so its doc 1
    // (the commons home) and doc 2 (the head document) exist, both PUBLISHED;
    // and node [1]'s own account chain untouched, at zero.
    let s = M3State::genesis();
    assert_eq!(s.entity_level(&a(&[1])), Some(Level::Node));
    assert!(s.is_allocated(&a(&[1])));
    // π₀ resolves in both directions: its id names the root prefix, and the
    // root address names it as ω.
    assert_eq!(s.principal_prefix(BOOTSTRAP_PRINCIPAL), Some(&a(&[1])));
    assert_eq!(s.effective_owner(&a(&[1])), Some(BOOTSTRAP_PRINCIPAL));
    // Empty frontiers: nothing else is allocated or registered yet.
    assert!(!s.is_allocated(&a(&[1, 0, 1])));
    assert_eq!(s.entity_level(&a(&[1, 0, 1])), None);
    // Unknown ids resolve to nothing (single-valued scan, §5).
    assert!(s.principal_prefix(ID1).is_none());
    assert!(!s.is_effective_owner(ID1, &a(&[1])));
}

#[test]
fn the_slice_prints_its_four_fields_and_their_contents() {
    // The slice a world embeds is reportable, so a test failure or a `dbg!` in
    // any engine can print it — the impl has to live here, since no downstream
    // crate may add it. Rendered from a POPULATED slice, so all four fields —
    // the three registries and the publication map — have contents to print
    // and not just names.
    let (k, _acct, _doc) = kernel_with_account_and_doc();
    let snap = k.snapshot();
    let dump = format!("{:?}", snap.world().m3());
    for field in ["frontiers", "nodes", "principals", "publication"] {
        assert!(dump.contains(field), "the dump omits {field}: {dump}");
    }
    // The contents ride along: the bootstrap principal and the delegate.
    assert!(dump.contains("PrincipalId(0)"), "{dump}");
    assert!(dump.contains("PrincipalId(1)"), "{dump}");
    // NOT: comparing two rendered dumps as an equality oracle. Every field
    // is an ORDERED collection since 2026-09-23 (`frontiers` moved off the
    // `im::HashMap` whose per-process `RandomState` once printed equal slices
    // in differing orders), so two equal slices now render alike — but the
    // rendering is a report, and `M3State`'s own `PartialEq` is the one that
    // compares by entries; it is what `journaled_types_survive_serde_round_trips`
    // asserts on.
}
