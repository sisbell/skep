//! Genesis — the engine's first own obligation: construct the initial world.
//!
//! There is no genesis configuration to hold, and no `GenesisConfig`: the
//! five reserved type addresses are compiled format constants —
//! `ReservedAddrs::format`, the ghost tumblers `1.1.0.1.0.1.0.1.x` for
//! x = 1..=5 — identical on every board because they are the format, not
//! because a sealed configuration enforces agreement. The registry every
//! consumer reads is M7's module constant (`skep_links::registry`), built
//! from them once per process under M7's own startup assertion, so nothing
//! here can drift and nothing here can fail.

use skep_arrangement::M5State;
use skep_content::ContentStore;
use skep_identity::IdentityState;
use skep_links::LinkState;
use skep_namespace::M3State;

use crate::grants::Grants;
use crate::publication;
use crate::world::{FormatStamp, World};

impl World {
    /// Returns Σ₀, the full genesis, one store at a time per its own design.
    ///
    /// M3 is seeded per `M3State::genesis`: the baptismal roots (node `[1]`,
    /// bootstrap principal π₀) and the system account seed (PUB-6.65,
    /// RES-304), whose four documents M3's card lists, all empty: three born
    /// published and one, the staging draft, born unpublished. M4 is empty
    /// (`ContentStore::default` — the permascroll starts with no content);
    /// M5 is empty (`M5State::genesis`: no arrangements, no provenance, no
    /// birth memo, no shot terms, no fork sources); and M7 holds `links = ∅`
    /// and empty hints (`LinkState::genesis`), read against the format
    /// registry — M7's module constant, whose five shipped classes include
    /// the PredLayer `pdef`/`pd_stable` registrations. Genesis mints no
    /// content and deposits no link, which is why the other three stay
    /// empty. It is a constant — deterministic with no inputs to hold
    /// constant — which is what discharges M2's byte-identical-genesis caller
    /// contract by construction; the World's own leading format stamp and
    /// M2's journal and checkpoint stamps, not a sealed configuration, name
    /// the format that wrote a base.
    ///
    /// The five reserved type addresses the M7 slice dispatches on are
    /// in-docuverse ghost tumblers: content positions of the registry node's
    /// doc 1, which `skep_namespace::ghost_position` spells. Nothing is
    /// seeded at them and nothing ever will be, and that is not this
    /// genesis's to guarantee: non-reissue — a reserved name never equals an
    /// allocated address — is M3's allocator floor, which
    /// `skep_namespace::GHOST_POSITIONS` names and M3 argues where the floor
    /// is written. So genesis seeds nothing at those five positions — M3's
    /// seed registers the ghost home document itself, as the system account's
    /// doc 1, and mints no content in it — and the ghost region needs nothing
    /// from it.
    ///
    /// Σ₀ carries its own derived hints, and must: under
    /// `Durability::InMemory` this value is the installed root — that mode
    /// does not load, so M2 never runs `WorldState::rebuild_derived` over it
    /// — and every in-memory caller (the conformance rig, the daemon's
    /// historical reads, the whole in-memory suite) reads through whatever
    /// hints it arrives with. It needs no rebuild because each derived
    /// structure over this authoritative state is seeded here as a rebuild
    /// would leave it: M7's hints, empty over an empty links map; M5's (whose
    /// rebuild is the identity); the exception set, which stores the
    /// unpublished side (PUB-7.5) and is built by the rebuild's own walk
    /// (`publication::seed`) over the one namespace this world carries, so
    /// it holds the one draft M3's seed registers — the system account's
    /// staging draft, owned by that account — and that document is withheld
    /// from the first moment, where an empty set would read it published
    /// (PUB-7.5's fail-open sign); and the grant fold, empty since no link
    /// exists to be a grant. The corollary is a maintainer's, and the system
    /// account seed exercises it: a genesis that seeds anything beyond M3's
    /// roots — a document, a link — must seed that entry's derived state
    /// beside it. The seed's three born-published documents seed nothing (no
    /// draft, no grant); its one unpublished document seeds its entry in the
    /// set. `Engine::check_hints` is the standing check that what is seeded
    /// here equals a from-authoritative rebuild, and the genesis suite runs
    /// it over bare Σ₀ (`genesis_seeds_each_store_per_its_design`).
    pub fn genesis() -> World {
        // One namespace, built once: the world carries it and the exception
        // set is seeded off it, so the set holds exactly the drafts the
        // slice beside it registers.
        let namespace = M3State::genesis();
        let drafts = publication::seed(&namespace);
        World {
            format: FormatStamp,
            namespace,
            content: ContentStore::default(),
            arrangement: M5State::genesis(),
            links: LinkState::genesis(),
            // The identity slice at Σ₀ is the fold's own genesis (AUTH-1.41):
            // no credential deposit exists, so no account is keyed and the
            // board is unclaimed — `Some`, as every loaded World must carry
            // it (AUTH-2.81), and carried rather than resolved.
            identity: Some(IdentityState::genesis()),
            identity_resolved: false,
            drafts,
            // Σ₀ has no links, so no grants — the fold's failure sign
            // (PUB-7.68: a seeded fold is empty only where no link is an
            // admitted record of the grants class) holds trivially here, a
            // world where empty and "nothing granted" coincide.
            grants: Grants::new(),
        }
    }
}
