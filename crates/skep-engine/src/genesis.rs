//! Genesis — the engine's first own obligation: construct the initial world.
//! There is no genesis configuration to hold (owner ruling, 2026-08-26,
//! second clause: `GenesisConfig` is RETIRED): the five reserved type
//! addresses are compiled format constants — `ReservedAddrs::format`, the
//! ghost tumblers `1.1.0.1.0.1.0.1.x` for x = 1..=5 — identical on every
//! board because they ARE the format, not because a sealed configuration
//! enforced agreement. The registry every consumer reads is built from them
//! by M7 (`TypeRegistry::build`, a startup assertion rather than an input
//! validation), so nothing here can drift and nothing here can fail.

use skep_arrangement::M5State;
use skep_content::ContentStore;
use skep_links::LinkState;
use skep_namespace::M3State;

use crate::publication::Drafts;
use crate::world::{FormatStamp, World};

impl World {
    /// Σ₀ — the full genesis, one store at a time per its own design:
    /// M3 seeded with the baptismal roots (`M3State::genesis`: node `[1]`,
    /// bootstrap principal π₀), M4 empty (`ContentStore::default` — the
    /// permascroll starts with no content), M5 empty (`M5State::genesis`:
    /// no arrangements, no provenance), and M7 with `links = ∅` under the
    /// format registry — the five shipped classes including the PredLayer
    /// `pdef`/`pd_stable` registrations (`LinkState::genesis`). Genesis
    /// creates exactly two things: the namespace roots and the empty
    /// docuverse. A CONSTANT — deterministic with no inputs to hold
    /// constant — which is what discharges M2's byte-identical-genesis
    /// caller contract by construction; the World's own leading format stamp
    /// and the journal's format stamp, not a sealed configuration, name the
    /// format that wrote a base.
    ///
    /// The five reserved type addresses the M7 slice dispatches on are
    /// in-docuverse GHOST TUMBLERS (owner ruling, 2026-08-26): content
    /// positions 1..=5 of doc 1 of account 1 — the operator's, by the
    /// claim-ceremony convention — of the registry node `1.1`. Nothing is
    /// seeded at them and nothing ever will be: collision-freedom ("a
    /// reserved name can never equal an allocated address") is the
    /// ALLOCATOR'S non-reissue guarantee, not this genesis's — M3 compiles
    /// the matching ghost-region floor (`skep_namespace::ghost_position`;
    /// the allocator reading is the-frontier-starts-past-the-region, since
    /// M3's compressed representation cannot skip an ordinal without
    /// allocating it), so the ceremony's doc-1 mint lands at its ordinary
    /// ordinal, the ghost positions sit inside that real doc-1, and its
    /// first content mint lands at position 6. The abolished out-of-tree
    /// `9.0.9.0.9.0.9.k` space argued from unreachability of a foreign
    /// subtree; no address space exists outside the docuverse.
    ///
    /// Σ₀ CARRIES ITS OWN DERIVED HINTS, and must: under
    /// `Durability::InMemory` this value IS the installed root — that mode
    /// does not load, so M2 never runs `WorldState::rebuild_derived` over it
    /// — and every in-memory caller (the conformance rig, the daemon's
    /// historical reads, the whole in-memory suite) reads through whatever
    /// hints it arrives with. That is why each slice above comes from its own
    /// genesis constructor rather than from a placeholder: `LinkState::genesis`
    /// builds a real registry over an empty links map, M5's rebuild is the
    /// identity, and the exception set is EMPTY because no document exists
    /// at Σ₀ to be a draft — the one world where an empty set and
    /// everything-published are the same true statement (PUB-7.5's fail-open
    /// sign has nothing to fail open over). `Engine::check_hints` is the
    /// standing check that what is seeded here equals a from-authoritative
    /// rebuild.
    pub fn genesis() -> World {
        World {
            format: FormatStamp,
            namespace: M3State::genesis(),
            content: ContentStore::default(),
            arrangement: M5State::genesis(),
            links: LinkState::genesis(),
            drafts: Drafts::new(),
        }
    }
}
