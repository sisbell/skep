//! The one concrete `World` and the one central `Record` enum, with the
//! `WorldState` implementation, the accessor-trait implementations, and the
//! record lifts — the Engine Composition Contract's "The engine crate
//! assembles" block, realized verbatim for the four state-contributing
//! stores (M3, M4, M5, M7). M6/M8/M9/M10 contribute no slice and no record
//! variant, so nothing of theirs appears here.

use serde::{Deserialize, Serialize};
use skep_arrangement::{HasM5, M5Rec, M5State};
use skep_content::{ContentStore, ContentWrite, HasContent};
use skep_kernel::WorldState;
use skep_links::{HasLinks, LinkRec, LinkState};
use skep_namespace::{HasM3, M3Rec, M3State};

/// The ONE concrete world: every store's authoritative slice, composed
/// (contract §The engine crate assembles), each field named for the store
/// whose slice it is. Fields are crate-private — every reader, the stores
/// included, reaches a slice through its accessor trait (contract hard rule:
/// "Reach slices through accessor traits, never field access on a concrete
/// world"); only the assembler's own construction, dispatch, and dump paths
/// touch the fields.
///
/// Field ORDER is the compatibility surface, not the field names: M2
/// checkpoints a world through bincode, which encodes a struct as its fields
/// in declaration order and carries no names, so a rename is byte-neutral for
/// recovery and a reordering is not.
///
/// INVARIANT — a world's derived state agrees with its authoritative state:
/// concretely, M7's skip-serialized registry and hints. TWO construction
/// paths establish it, and the third does not. [`World::genesis`] establishes
/// it, each slice arriving from its own genesis constructor; and
/// [`WorldState::rebuild_derived`] re-establishes it, which M2 runs over
/// every base it loads, before replay. The `Deserialize` derived below
/// establishes nothing — it leaves M7's registry at serde's seed, which
/// "registers nothing, reports every shipped endset as `⟨⟩` and holds none of
/// `TypeRegistry`'s invariant", in `LinkState::registry`'s own words. So a
/// world decoded from bytes is not one until the rebuild has run over it.
/// That gate cannot be closed here: `WorldState: DeserializeOwned` forces the
/// impl to exist, and this type is public, so the only defence is the
/// discipline of the one mode that skips the rebuild —
/// `Durability::InMemory` installs the passed world as the root exactly as
/// given, and [`crate::EngineStores::new`] states the precondition for the
/// kernels built that way and what reads answer when it is violated.
///
/// THREE OBLIGATIONS `WorldState` places on this type that M2 cannot check,
/// each discharged by a fact about the slices rather than about this file.
/// `Clone` must be cheap, because M2 clones a world per `transact` while
/// holding the applier lock: all four slices are `im` persistent structures,
/// so the `..self.clone()` in [`WorldState::apply`] is four root clones.
/// `Drop` must not unwind, because M2 drops the previous root inside the
/// atomic install: no type in the world's closure implements `Drop` at all.
/// And this type's and [`Record`]'s `Deserialize` must terminate and must not
/// exhaust the stack on any byte string: that closure holds no recursive
/// type, so decode depth is a property of the types and not of the bytes. A
/// slice that moves to an eagerly-copied collection, or grows a recursive
/// value, breaks one of these where the obligation's own text is a crate
/// away.
#[derive(Clone, Serialize, Deserialize)]
pub struct World {
    pub(crate) namespace: M3State,
    pub(crate) content: ContentStore,
    pub(crate) arrangement: M5State,
    pub(crate) links: LinkState,
}

/// The ONE central record enum: one variant per store record type (contract
/// §The engine crate assembles), each named for the store whose delta it
/// carries.
///
/// The store crates name their own slice and record types by module ordinal
/// — `M3State`/`M3Rec`/`apply_m3`, `M5State`/`M5Rec`/`apply_m5`, and the
/// accessor methods `m3()`/`m5()` with them — while a slice here is named for
/// what it holds. So the seam reads `Record::Namespace(x) => …apply_m3(x)`
/// and `HasM3::m3` returns the `namespace` field: the store's word on the
/// store's side of the seam, the slice's word on this one. Neither side is a
/// mis-transcription of the other.
///
/// The engine only `From`-lifts and folds these — it never constructs a
/// store's record (M4's `ContentWrite` fields and M5's `M5Rec` variants are
/// non-constructible here by design, so each store's sole-constructor
/// invariant survives assembly). Variant ORDER carries the same bincode
/// obligation as `World`'s fields: variants encode by index, so a rename is
/// byte-neutral for replay and a reordering is not.
#[derive(Clone, Serialize, Deserialize)]
pub enum Record {
    Namespace(M3Rec),
    Content(ContentWrite),
    Arrangement(M5Rec),
    Links(LinkRec),
}

impl WorldState for World {
    type Record = Record;

    /// The one fold step (M2's `apply` obligation): dispatch each variant
    /// into its store's own pure/total/deterministic fold, replacing exactly
    /// that store's slice (contract §The engine crate assembles). No
    /// semantics here — the folds own every decision.
    fn apply(&self, r: &Record) -> World {
        match r {
            Record::Namespace(x) => {
                World { namespace: self.namespace.apply_m3(x), ..self.clone() }
            }
            Record::Content(x) => World { content: self.content.apply_write(x), ..self.clone() },
            Record::Arrangement(x) => {
                World { arrangement: self.arrangement.apply_m5(x), ..self.clone() }
            }
            Record::Links(x) => World { links: self.links.apply_link(x), ..self.clone() },
        }
    }

    /// THE recovery order — the one place the cross-store rebuild sequence at
    /// load is stated (runs once, before replay; M2 §7).
    ///
    /// Order: M3 → M4 → M5 → M7, the stores' dependency (DAG) order. Why: a
    /// store's hint rebuild may only ever read slices UPSTREAM of it (a
    /// downstream read would invert the module DAG), so rebuilding in
    /// dependency order guarantees every slice a rebuild could legitimately
    /// consult is already restored. As built, no rebuild reads a foreign
    /// slice at all — M3 and M4 are fully serialized (M2's default identity;
    /// their docs say so), M5's `rebuild_derived` is the identity (no
    /// skip-serialized hints in v1), and M7's reconstructs its registry from
    /// the compiled format constants and its hints from its OWN links map —
    /// so the order is future-proofing, pinned here and held to by the
    /// recovery-equivalence test.
    ///
    /// Infallible by M2's trait, and fail-stop in fact: the rebuilds composed
    /// here run over state that was just DESERIALIZED, and M7's asserts what
    /// it needs of it (that every stored link key is T4-valid and
    /// element-level; its registry is the compiled format constants and
    /// cannot fail to build). With no error channel to refuse through, a
    /// base that violates any of those panics rather than returning — inside
    /// `Kernel::open`, after that checkpoint loaded, so M2's next-older-base
    /// fallback does not get its turn.
    fn rebuild_derived(self) -> Self {
        let World { namespace, content, arrangement, links } = self;
        // M3, then M4: neither rebuilds — both slices are fully serialized, so
        // M2's default identity is the whole of their recovery, and their
        // places in the order are held open rather than skipped.
        let arrangement = arrangement.rebuild_derived();
        let links = links.rebuild_derived();
        World { namespace, content, arrangement, links }
    }
}

// The accessor-trait implementations — the read seam each store codes against
// (contract §What every store crate provides, item 3).

impl HasM3 for World {
    fn m3(&self) -> &M3State {
        &self.namespace
    }
}

impl HasContent for World {
    fn content(&self) -> &ContentStore {
        &self.content
    }
}

impl HasM5 for World {
    fn m5(&self) -> &M5State {
        &self.arrangement
    }
}

impl HasLinks for World {
    fn links(&self) -> &LinkState {
        &self.links
    }
}

// The record lifts — the write-side mirror of the accessors: stores return
// their OWN record type and the caller lifts with `.into()` (contract hard
// rule: "Return your own XRec, never the central Record").

impl From<M3Rec> for Record {
    fn from(r: M3Rec) -> Record {
        Record::Namespace(r)
    }
}

impl From<ContentWrite> for Record {
    fn from(r: ContentWrite) -> Record {
        Record::Content(r)
    }
}

impl From<M5Rec> for Record {
    fn from(r: M5Rec) -> Record {
        Record::Arrangement(r)
    }
}

impl From<LinkRec> for Record {
    fn from(r: LinkRec) -> Record {
        Record::Links(r)
    }
}
