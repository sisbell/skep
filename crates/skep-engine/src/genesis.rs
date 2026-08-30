//! Genesis — the engine's first own obligation: construct the initial world,
//! holding the one type configuration in ONE place so that the registry every
//! consumer reads (M7's slice validates it; the engine and M9 share that one
//! instance) rests on a single set of validated inputs and cannot drift.

use skep_address::{validate, Address, Nat, Tumbler};
use skep_arrangement::M5State;
use skep_content::ContentStore;
use skep_links::{LinkState, RegistryError, ReservedAddrs, ShippedType, TypeConfig};
use skep_namespace::M3State;

use crate::world::World;

/// The engine's genesis input (the genesis seam), which is exactly M7's
/// [`TypeConfig`]: the five reserved type addresses — including the PredLayer
/// registration agreement's `pdef`/`pd_stable`, whose `Unary/⊤/{}`
/// registrations `TypeRegistry::build` seeds itself — plus the app-declared
/// types.
///
/// Every consumer is fed from this one value: [`World::genesis`] seals it
/// into M7's `LinkState`, which validates it into the registry
/// [`crate::Engine::open`] then shares out, and
/// [`crate::Engine::coordinator`] hands both to M9, whose
/// validate-once-or-fail catalog projection re-checks the configuration
/// against that registry — so residual drift is caught at assembly.
///
/// M2's caller contract: the SAME configuration must be passed on every
/// `open()` of a given journal (genesis must be byte-identical); the config
/// is data precisely so the binary can hold it constant — and `Eq` is here so
/// that a binary holding one can say so, against the value it stored, before
/// an open turns the question into a recovery.
///
/// There is deliberately no `Default`. [`GenesisConfig::standard`] is not a
/// neutral value but the format-pinned one, and which configuration a journal
/// was sealed under is a decision every caller must make visibly; a `Default`
/// is how it stops being made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisConfig {
    /// The type configuration, carried whole so no consumer is handed halves
    /// that could arrive matched at one door and mismatched at the next.
    pub types: TypeConfig,
}

/// The five shipped classes, in `ShippedType` declaration order — the ONE
/// list, held beside the configuration that names them. Every walk over the
/// shipped set reads it here: [`crate::Engine::open`]'s genesis-drift check
/// and the world dump's per-class hint enumeration. A second copy is how one
/// of those two silently comes to cover four classes out of five.
pub(crate) const SHIPPED: [ShippedType; 5] = [
    ShippedType::Retired,
    ShippedType::Supersedes,
    ShippedType::Retraction,
    ShippedType::PredDef,
    ShippedType::PredStable,
];

/// A standard reserved type address: element-level `9.0.9.0.9.0.9.k` —
/// subspace 9 ∉ {s_C, s_L} (reserved-isolation), under node `[9]`, which is
/// not a descendant of the bootstrap node `[1]` and so can never be admitted
/// by `register_node`; no address under it is ever mintable, so a reserved
/// name can never equal an allocated address.
fn reserved_addr(k: u32) -> Address {
    let comps = [9u32, 0, 9, 0, 9, 0, 9, k].into_iter().map(Nat::from);
    let t = Tumbler::new(comps).expect("an eight-component sequence is nonempty");
    validate(t).expect("9.0.9.0.9.0.9.k is T4-valid by construction")
}

impl GenesisConfig {
    /// The standard configuration: the five reserved addresses at ordinals
    /// 1–5 of the out-of-tree subspace above, and no app decls. STABLE — a
    /// journal opened under this config must reopen under it (M2's
    /// byte-identical-genesis contract), so these values are fixed for the
    /// life of the format, never edited.
    pub fn standard() -> GenesisConfig {
        GenesisConfig {
            types: TypeConfig {
                reserved: ReservedAddrs {
                    pred_def: reserved_addr(1),
                    pred_stable: reserved_addr(2),
                    retired: reserved_addr(3),
                    supersedes: reserved_addr(4),
                    retraction: reserved_addr(5),
                },
                decls: Vec::new(),
            },
        }
    }
}

impl World {
    /// Σ₀ — the full genesis, one store at a time per its own design:
    /// M3 seeded with the baptismal roots (`M3State::genesis`: node `[1]`,
    /// bootstrap principal π₀), M4 empty (`ContentStore::default` — the
    /// permascroll starts with no content), M5 empty (`M5State::genesis`:
    /// no arrangements, no provenance), and M7 with `links = ∅` and the
    /// validated, sealed type config — the five shipped classes including
    /// the PredLayer `pdef`/`pd_stable` registrations
    /// (`LinkState::genesis`). Deterministic given `cfg`, per M2's
    /// byte-identical-genesis caller contract.
    ///
    /// Σ₀ CARRIES ITS OWN DERIVED HINTS, and must: under
    /// `Durability::InMemory` this value IS the installed root — that mode
    /// does not load, so M2 never runs `WorldState::rebuild_derived` over it
    /// — and every in-memory caller (the conformance rig, the daemon's
    /// historical reads, the whole in-memory suite) reads through whatever
    /// hints it arrives with. That is why each slice above comes from its own
    /// genesis constructor rather than from a placeholder: `LinkState::genesis`
    /// builds a real registry over an empty links map, and M5's rebuild is the
    /// identity. `Engine::check_hints` is the standing check that what is
    /// seeded here equals a from-authoritative rebuild.
    pub fn genesis(cfg: &GenesisConfig) -> Result<World, RegistryError> {
        Ok(World {
            namespace: M3State::genesis(),
            content: ContentStore::default(),
            arrangement: M5State::genesis(),
            links: LinkState::genesis(cfg.types.clone())?,
        })
    }
}
