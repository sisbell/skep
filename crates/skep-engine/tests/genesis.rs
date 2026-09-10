//! Genesis: the initial world seeds each store per its own design, and the
//! registry built from the compiled format constants (owner ruling,
//! 2026-08-26 — `GenesisConfig` is retired) is ONE process constant, which
//! M7's slice and the engine handle each read rather than hold and M9's
//! catalog projects. The five reserved type addresses are
//! in-docuverse ghost tumblers, and the property the abolished 9-space
//! bought by unreachability is re-proven here through the real ops: the
//! allocator never issues them.

mod common;

use common::*;
use skep_arrangement::HasM5;
use skep_content::{HasContent, Val};
use skep_engine::World;
use skep_links::{coverage_class, HasLinks, ReservedAddrs, ShippedType, View};
use skep_namespace::{ghost_home_doc, ghost_position, HasM3, BOOTSTRAP_PRINCIPAL, GHOST_POSITIONS};

/// M7's own list of the five — read rather than restated, so a walk here
/// cannot come to cover four classes out of five.
const SHIPPED: [ShippedType; 5] = ShippedType::ALL;

/// Genesis seeds M3's baptismal roots and leaves M4/M5/M7's stores empty —
/// exactly two things exist: the namespace roots and the empty docuverse.
#[test]
fn genesis_seeds_each_store_per_its_design() {
    let engine = mem_engine();
    let snap = engine.kernel().snapshot();
    let world = snap.world();

    // M3: node [1] registered, owned by the bootstrap principal.
    assert_eq!(world.m3().entity_level(&node1()), Some(skep_address::Level::Node));
    assert_eq!(world.m3().effective_owner(&node1()), Some(BOOTSTRAP_PRINCIPAL));

    // M4: the permascroll starts empty.
    assert!(world.content().is_empty());

    // M5: no arrangements (any document reads as absent-empty).
    assert_eq!(world.m5().content_count(&node1()), nat(0));

    // M7: no links; the whole audit slice is empty.
    assert!(world.links().match_links(&[], View::Audit).is_empty());
}

/// Genesis is a compiled constant: two constructions are byte-identical
/// through M2's own checkpoint encoding — the determinism that used to be a
/// caller contract over a passed configuration is now a fact with no inputs.
#[test]
fn two_geneses_are_byte_identical() {
    let a = bincode::serialize(&World::genesis()).expect("a world serializes");
    let b = bincode::serialize(&World::genesis()).expect("a world serializes");
    assert_eq!(a, b, "genesis must be one value, byte for byte");
}

/// The genesis seam: ONE registry serves every shipped class. The engine's
/// accessor and a world's own slice both read `skep_links::registry()`, a
/// process constant built from the compiled format constants and held by
/// neither of them — so there is no second instance for a comparison to
/// catch, and their agreement is definitional rather than checkable.
///
/// What remains checkable is COVERAGE: a shipped class the registry does not
/// register has no `Registration`, and the write gates and folds keyed on its
/// coverage class would find none. The two reads are named side by side so
/// that an accessor which stopped forwarding to the constant fails here
/// rather than at a write gate.
#[test]
fn the_one_registry_registers_every_shipped_class() {
    let engine = mem_engine();
    let snap = engine.kernel().snapshot();
    let links = snap.world().links();

    for ty in SHIPPED {
        let ours = engine.registry().reserved_type(ty);
        assert!(
            engine.registry().registration(&coverage_class(ours)).is_some(),
            "shipped class {ty:?} must be registered"
        );
        assert_eq!(ours, links.reserved_type(ty), "shipped class {ty:?}");
    }
}

/// The third consumer: M9's catalog is a pure projection of that same
/// registry (assembly is infallible now — nothing is twice-passed), and the
/// empty rule registry is vacuously quiescent.
#[test]
fn coordinator_projects_the_one_registry() {
    let engine = mem_engine();
    let coord = engine.coordinator();

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

/// The five reserved addresses are format state — the owner-pinned ghost
/// tumblers (2026-08-26): content positions 1–5 of doc 1 of account 1 of the
/// registry node 1.1, in the ruling's assignment order. Pinned as literal
/// text rather than re-derived from the constructor that makes them — that
/// constructor is the thing that could change — and format-frozen the day
/// this merged: an edit silently mis-dispatches every journal in existence.
#[test]
fn the_format_pins_its_five_reserved_addresses() {
    let reserved = ReservedAddrs::format();
    assert_eq!(reserved.pred_def.to_string(), "1.1.0.1.0.1.0.1.1");
    assert_eq!(reserved.pred_stable.to_string(), "1.1.0.1.0.1.0.1.2");
    assert_eq!(reserved.retired.to_string(), "1.1.0.1.0.1.0.1.3");
    assert_eq!(reserved.supersedes.to_string(), "1.1.0.1.0.1.0.1.4");
    assert_eq!(reserved.retraction.to_string(), "1.1.0.1.0.1.0.1.5");
    // The engine's registry serves exactly these, so the dispatch keys and
    // the pinned literals are one set.
    let engine = mem_engine();
    for (ty, addr) in [
        (ShippedType::PredDef, &reserved.pred_def),
        (ShippedType::PredStable, &reserved.pred_stable),
        (ShippedType::Retired, &reserved.retired),
        (ShippedType::Supersedes, &reserved.supersedes),
        (ShippedType::Retraction, &reserved.retraction),
    ] {
        assert_eq!(engine.registry().reserved_type(ty), &skep_links::enc(std::slice::from_ref(addr)));
    }
}

/// Non-reissue end to end, through the assembled engine — the load-bearing
/// clause of the ghost-tumbler ruling (1c): dispatch is by number, so a
/// fresh mint landing on the `retraction` value would be catastrophic. The
/// ghost region is REACHABLE territory (that is what the old 9-space test
/// proved could never happen by unreachability): the registry node is
/// admitted, the claim ceremony's delegate lands the operator at account 1,
/// its doc-1 mints at its ordinary ordinal — and the doc's content frontier
/// provably starts past the region, so INSERT's content lands from position
/// 6 and nothing exists at any ghost tumbler, before or after.
#[test]
fn no_reserved_address_is_ever_minted_and_the_ceremony_is_not_renumbered() {
    let engine = mem_engine();
    let reserved = ReservedAddrs::format();

    // Before any of the lineage exists: nothing at the five, anywhere.
    {
        let snap = engine.kernel().snapshot();
        for addr in [
            &reserved.pred_def,
            &reserved.pred_stable,
            &reserved.retired,
            &reserved.supersedes,
            &reserved.retraction,
        ] {
            assert!(!snap.world().m3().is_allocated(addr), "{addr} allocated at genesis");
        }
    }

    // The registry node 1.1, its operator (the claim ceremony's delegate,
    // at account ordinal 1 by next-form), and the ceremony's doc-1 — all at
    // their ordinary ordinals: the pin renumbers nothing.
    engine.namespace().register_node(tum(&[1, 1])).expect("the registry node is admissible");
    let (operator, _) = engine
        .namespace()
        .delegate(BOOTSTRAP_PRINCIPAL, tum(&[1, 1, 0, 1]), USER)
        .expect("the operator lands at account 1");
    assert_eq!(operator, addr(&[1, 1, 0, 1]));
    let (doc1, _) = engine
        .namespace()
        .create_new_document(USER, &operator, None)
        .expect("the ceremony's doc-1");
    assert_eq!(doc1, ghost_home_doc(), "doc-1 IS the ghost home document");

    // INSERT drives the content chain: the permascroll writes land from
    // position GHOST_POSITIONS + 1, and keep going contiguously. The
    // ceremony's doc-1 is born published, so the write is what the ceremony's
    // own record atom is — a DECLARED deposit at its fresh positions
    // (PUB-2.59, PUB-2.63).
    let (start, _) = engine
        .vstream()
        .insert(OWNER, &doc1, vp(1, 1), vec![Val::new(vec![b'a']), Val::new(vec![b'b'])], true)
        .expect("insert into the ghost doc succeeds");
    assert_eq!(
        start,
        addr(&[1, 1, 0, 1, 0, 1, 0, 1, GHOST_POSITIONS + 1]),
        "the first content mint lands past the ghost region"
    );

    let snap = engine.kernel().snapshot();
    for x in 1..=GHOST_POSITIONS {
        assert!(
            !snap.world().m3().is_allocated(&ghost_position(x)),
            "ghost {x} must stay unallocated with the chain past it"
        );
    }
    assert!(snap.world().m3().is_allocated(&start));
}
