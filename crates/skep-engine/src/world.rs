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
/// (contract §The engine crate assembles). Fields are crate-private — every
/// reader, the stores included, reaches a slice through its accessor trait
/// (contract hard rule: "Reach slices through accessor traits, never field
/// access on a concrete world"); only the assembler's own construction,
/// dispatch, and observation paths touch the fields.
#[derive(Clone, Serialize, Deserialize)]
pub struct World {
    pub(crate) m3: M3State,
    pub(crate) content: ContentStore,
    pub(crate) m5: M5State,
    pub(crate) links: LinkState,
}

/// The ONE central record enum: one variant per store record type (contract
/// §The engine crate assembles). Variant names are the ones the store docs
/// cite (`Record::M3`, `Record::Content`, `Record::M5`, `Record::Links`).
/// The engine only `From`-lifts and folds these — it never constructs a
/// store's record (M4's `ContentWrite` fields and M5's `M5Rec` variants are
/// non-constructible here by design, so each store's sole-constructor
/// invariant survives assembly).
#[derive(Clone, Serialize, Deserialize)]
pub enum Record {
    M3(M3Rec),
    Content(ContentWrite),
    M5(M5Rec),
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
            Record::M3(x) => World { m3: self.m3.apply_m3(x), ..self.clone() },
            Record::Content(x) => World { content: self.content.apply_write(x), ..self.clone() },
            Record::M5(x) => World { m5: self.m5.apply_m5(x), ..self.clone() },
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
    /// its OWN serialized `TypeConfig` and its hints from its OWN
    /// links map — so the order is future-proofing, pinned here and held to
    /// by the recovery-equivalence test.
    fn rebuild_derived(self) -> Self {
        let World { m3, content, m5, links } = self;
        // M3, then M4: neither rebuilds — both slices are fully serialized, so
        // M2's default identity is the whole of their recovery, and their
        // places in the order are held open rather than skipped.
        let m5 = m5.rebuild_derived();
        let links = links.rebuild_derived();
        World { m3, content, m5, links }
    }
}

// The accessor-trait implementations — the read seam each store codes against
// (contract §What every store crate provides, item 3).

impl HasM3 for World {
    fn m3(&self) -> &M3State {
        &self.m3
    }
}

impl HasContent for World {
    fn content(&self) -> &ContentStore {
        &self.content
    }
}

impl HasM5 for World {
    fn m5(&self) -> &M5State {
        &self.m5
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
        Record::M3(r)
    }
}

impl From<ContentWrite> for Record {
    fn from(r: ContentWrite) -> Record {
        Record::Content(r)
    }
}

impl From<M5Rec> for Record {
    fn from(r: M5Rec) -> Record {
        Record::M5(r)
    }
}

impl From<LinkRec> for Record {
    fn from(r: LinkRec) -> Record {
        Record::Links(r)
    }
}
