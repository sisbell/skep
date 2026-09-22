//! Genesis — the engine's first own obligation: construct the initial world.
//! There is no genesis configuration to hold (owner ruling, 2026-08-26,
//! second clause: `GenesisConfig` is RETIRED): the five reserved type
//! addresses are compiled format constants — `ReservedAddrs::format`, the
//! ghost tumblers `1.1.0.1.0.1.0.1.x` for x = 1..=5 — identical on every
//! board because they ARE the format, not because a sealed configuration
//! enforced agreement. The registry every consumer reads is M7's module
//! constant (`skep_links::registry`), built from them once per process under
//! M7's own startup assertion, so nothing here can drift and nothing here can
//! fail.

use skep_arrangement::M5State;
use skep_content::ContentStore;
use skep_links::LinkState;
use skep_namespace::M3State;

use crate::grants::Grants;
use crate::publication::Drafts;
use crate::world::{FormatStamp, World};

impl World {
    /// Σ₀ — the full genesis, one store at a time per its own design:
    /// M3 seeded with the baptismal roots (`M3State::genesis`: node `[1]`,
    /// bootstrap principal π₀), M4 empty (`ContentStore::default` — the
    /// permascroll starts with no content), M5 empty (`M5State::genesis`:
    /// no arrangements, no provenance, no birth memo), and M7 with
    /// `links = ∅` and empty hints (`LinkState::genesis`), read against the
    /// format registry — M7's module constant, whose five shipped classes
    /// include the PredLayer `pdef`/`pd_stable` registrations. Genesis
    /// creates exactly two things: the namespace roots and the empty
    /// docuverse. A CONSTANT — deterministic with no inputs to hold constant
    /// — which is what discharges M2's byte-identical-genesis caller contract
    /// by construction; the World's own leading format stamp and the
    /// journal's format stamp, not a sealed configuration, name the format
    /// that wrote a base.
    ///
    /// The five reserved type addresses the M7 slice dispatches on are
    /// in-docuverse GHOST TUMBLERS (owner ruling, 2026-08-26): content
    /// positions of the registry node's doc 1, which
    /// `skep_namespace::ghost_position` spells. Nothing is seeded at them and
    /// nothing ever will be, and that is not this genesis's to guarantee:
    /// non-reissue — a reserved name never equals an allocated address — is
    /// M3's allocator floor, which `skep_namespace::GHOST_POSITIONS` names and
    /// M3 argues where the floor is written. So genesis seeds the namespace
    /// roots alone, and the ghost region needs nothing from it.
    ///
    /// Σ₀ CARRIES ITS OWN DERIVED HINTS, and must: under
    /// `Durability::InMemory` this value IS the installed root — that mode
    /// does not load, so M2 never runs `WorldState::rebuild_derived` over it
    /// — and every in-memory caller (the conformance rig, the daemon's
    /// historical reads, the whole in-memory suite) reads through whatever
    /// hints it arrives with. It needs no rebuild because every derived
    /// structure over THIS authoritative state is empty — M3's roots register
    /// no document, and the other three slices hold nothing — and each is
    /// seeded empty here: M7's hints over an empty links map, M5's (whose
    /// rebuild is the identity), the exception set, since no document exists
    /// at Σ₀ to be a draft — the one world where an empty set and
    /// everything-published are the same true statement (PUB-7.5's fail-open
    /// sign has nothing to fail open over) — and the grant fold, since no
    /// link exists to be a grant. The corollary is a maintainer's: a genesis
    /// that seeds anything beyond M3's roots — a document, a link — must seed
    /// that entry's derived state beside it. `Engine::check_hints` is the
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
            // Σ₀ has no links, so no grants — the fold's fail-open sign
            // (PUB-7.68: an empty fold ⟺ an empty link map) holds trivially
            // here, the one world where empty and "nothing granted" coincide.
            grants: Grants::new(),
        }
    }
}
