//! Genesis: the initial world seeds each store per its own design, and the
//! one `TypeConfig` reaches every registry consumer — M7's genesis-sealed
//! slice, the engine handle, and M9's validate-once-or-fail catalog
//! projection — as ONE validated registry, not as copies that could drift.

mod common;

use std::sync::Arc;

use common::*;
use skep_address::{content_subspace, link_subspace, Level};
use skep_arrangement::HasM5;
use skep_content::HasContent;
use skep_engine::{Engine, EngineError, GenesisConfig};
use skep_links::{coverage_class, HasLinks, RegistryError, ShippedType, View};
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

/// The genesis seam: the registry the engine publishes IS the one M7's slice
/// validated from its own sealed configuration — one instance, so the two
/// consumers cannot disagree by construction rather than by comparison — and
/// every shipped class is registered in it.
#[test]
fn the_engine_publishes_the_slice_s_own_registry() {
    let engine = mem_engine();
    let snap = engine.kernel().snapshot();
    let links = snap.world().links();

    assert!(
        Arc::ptr_eq(engine.registry(), links.registry()),
        "the engine must share M7's registry, not rebuild a second one"
    );
    for ty in SHIPPED {
        let ours = engine.registry().reserved_type(ty);
        assert_eq!(ours, links.reserved_type(ty), "shipped class {ty:?}");
        assert!(
            engine.registry().registration(&coverage_class(ours)).is_some(),
            "shipped class {ty:?} must be registered"
        );
    }
}

/// The third consumer: M9's catalog projection validates against that same
/// registry at assembly (drift would fail `coordinator()` here), and the
/// empty rule registry is vacuously quiescent.
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

/// The five reserved addresses are format state: a journal sealed under them
/// must reopen under them, so an edit here silently mis-recovers every journal
/// in existence. Pinned as literal text rather than re-derived from the
/// constructor that makes them — that constructor is the thing that could
/// change.
#[test]
fn the_standard_config_pins_its_five_reserved_addresses() {
    let cfg = GenesisConfig::standard();
    let r = &cfg.types.reserved;
    assert_eq!(r.pred_def.to_string(), "9.0.9.0.9.0.9.1");
    assert_eq!(r.pred_stable.to_string(), "9.0.9.0.9.0.9.2");
    assert_eq!(r.retired.to_string(), "9.0.9.0.9.0.9.3");
    assert_eq!(r.supersedes.to_string(), "9.0.9.0.9.0.9.4");
    assert_eq!(r.retraction.to_string(), "9.0.9.0.9.0.9.5");
    assert!(cfg.types.decls.is_empty(), "the standard config declares no app types");
}

/// Reserved-isolation, the property that makes a reserved address safe as a
/// type key: outside {s_C, s_L}, and under a node the bootstrap node is not,
/// so no mint and no `register_node` can ever issue one and a reserved name
/// can never equal an allocated address.
#[test]
fn no_reserved_address_can_ever_be_minted() {
    let engine = mem_engine();
    let snap = engine.kernel().snapshot();
    let r = GenesisConfig::standard().types.reserved;

    for addr in [r.pred_def, r.pred_stable, r.retired, r.supersedes, r.retraction] {
        assert_ne!(addr.subspace(), Some(&content_subspace()), "{addr} sits in s_C");
        assert_ne!(addr.subspace(), Some(&link_subspace()), "{addr} sits in s_L");
        assert_ne!(
            addr.node_field(),
            node1().node_field(),
            "{addr} is under the bootstrap node, so a mint could reach it"
        );
        assert!(!snap.world().m3().is_allocated(&addr), "{addr} is an allocated address");
    }
}

/// An invalid type configuration is refused at open — validate-once-or-fail,
/// before any kernel exists.
#[test]
fn invalid_genesis_is_refused() {
    // A reserved type address inside the content subspace (s_C = 1) violates
    // reserved-isolation.
    let mut bad = GenesisConfig::standard();
    bad.types.reserved.retired = a(&[9, 0, 9, 0, 9, 0, 1, 1]);
    match Engine::open(mem_cfg(), bad) {
        Err(EngineError::Registry(RegistryError::ReservedSubspaceClash)) => {}
        Err(other) => panic!("expected ReservedSubspaceClash, got {other:?}"),
        Ok(_) => panic!("an invalid genesis config must not open"),
    }
}
