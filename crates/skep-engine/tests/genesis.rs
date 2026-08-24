//! Genesis: the initial world seeds each store per its own design, and the
//! one `(reserved, decls)` configuration feeds every registry consumer —
//! M7's genesis-sealed slice, the engine-built `Arc<TypeRegistry>`, and
//! M9's validate-once-or-fail catalog projection — without drift.

mod common;

use common::*;
use skep_address::Level;
use skep_arrangement::HasM5;
use skep_content::HasContent;
use skep_engine::{Engine, EngineError, GenesisConfig};
use skep_links::{coverage_class, HasLinks, RegistryError, ReservedAddrs, ShippedType, View};
use skep_namespace::{HasM3, BOOTSTRAP_PRINCIPAL};

const SHIPPED: [ShippedType; 5] = [
    ShippedType::Retired,
    ShippedType::Supersedes,
    ShippedType::Retraction,
    ShippedType::PredDef,
    ShippedType::PredStable,
];

/// Genesis seeds M3's baptismal roots and leaves M4/M5/M7's stores empty.
#[test]
fn genesis_seeds_each_store_per_its_design() {
    let engine = mem_engine();
    let snap = engine.kernel().snapshot();
    let w = snap.world();

    // M3: node [1] registered, owned by the bootstrap principal.
    assert_eq!(w.m3().entity_level(&node1()), Some(Level::Node));
    assert_eq!(w.m3().effective_owner(&node1()), Some(BOOTSTRAP_PRINCIPAL));

    // M4: the permascroll starts empty.
    assert!(w.content().is_empty());

    // M5: no arrangements (any document reads as absent-empty).
    assert_eq!(w.m5().content_count(&node1()), n(0));

    // M7: no links; the whole audit slice is empty.
    assert!(w.links().match_links(&[], View::Audit).is_empty());
}

/// The genesis seam: the engine-built registry and the world's own sealed
/// registry are fed from the one configuration and agree on every shipped
/// class — endset and registration alike.
#[test]
fn both_registry_consumers_agree() {
    let engine = mem_engine();
    let snap = engine.kernel().snapshot();
    let links = snap.world().links();

    for ty in SHIPPED {
        let ours = engine.registry().reserved_type(ty);
        let theirs = links.reserved_type(ty);
        assert_eq!(ours, theirs, "engine registry and LinkState registry disagree on {ty:?}");
        assert!(
            engine.registry().registration(&coverage_class(ours)).is_some(),
            "shipped class {ty:?} must be registered"
        );
    }
}

/// The third consumer: M9's catalog projection validates against the
/// engine-built registry at assembly (drift would fail `coordinator()`
/// here), and the empty rule registry is vacuously quiescent.
#[test]
fn coordinator_projects_the_one_registry() {
    let engine = mem_engine();
    let coord = engine
        .coordinator()
        .expect("the catalog projection validates against the same genesis config");

    for ty in SHIPPED {
        assert_eq!(
            coord.reserved_type(ty),
            engine.registry().reserved_type(ty),
            "coordinator catalog and engine registry disagree on {ty:?}"
        );
    }

    let snap = engine.kernel().snapshot();
    assert!(coord.quiescent(&snap), "an empty rule registry is quiescent");
}

/// An invalid type configuration is refused at open — validate-once-or-fail,
/// before any kernel exists.
#[test]
fn invalid_genesis_is_refused() {
    // A reserved type address inside the content subspace (s_C = 1) violates
    // reserved-isolation.
    let mut reserved: ReservedAddrs = GenesisConfig::standard().reserved;
    reserved.retired = a(&[9, 0, 9, 0, 9, 0, 1, 1]);
    let bad = GenesisConfig { reserved, decls: Vec::new() };
    match Engine::open(mem_cfg(), bad) {
        Err(EngineError::Registry(RegistryError::ReservedSubspaceClash)) => {}
        Err(other) => panic!("expected ReservedSubspaceClash, got {other:?}"),
        Ok(_) => panic!("an invalid genesis config must not open"),
    }
}
