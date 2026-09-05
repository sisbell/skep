//! The one concrete `World` and the one central `Record` enum, with the
//! `WorldState` implementation, the accessor-trait implementations, and the
//! record lifts — the Engine Composition Contract's "The engine crate
//! assembles" block, realized verbatim for the four state-contributing
//! stores (M3, M4, M5, M7) — plus the two things the assembled world carries
//! that no store does: its checkpoint FORMAT STAMP and the exception set
//! (`crate::publication`). M6/M8/M9/M10 contribute no slice and no record
//! variant, so nothing of theirs appears here.

use serde::{Deserialize, Serialize};
use skep_arrangement::{HasM5, M5Rec, M5State};
use skep_content::{ContentStore, ContentWrite, HasContent};
use skep_kernel::WorldState;
use skep_links::{HasLinks, LinkRec, LinkState};
use skep_namespace::{HasM3, M3Rec, M3State};

use crate::publication::{self, Drafts};

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
/// recovery and a reordering is not. The `FormatStamp` LEADS, and that is
/// load-bearing: it is the first thing a decoder reads, so a checkpoint
/// written under any other World layout — the pre-publication-bit layout
/// above all (PUB-7.8) — is refused at byte 0 by a value comparison, before
/// any slice's bytes are read as another's. The skip-serialized `drafts` sits
/// outside the surface: it occupies no bytes.
///
/// INVARIANT — a world's derived state agrees with its authoritative state:
/// concretely, M7's skip-serialized hints and the engine's own exception set.
/// TWO construction paths establish it, and the third does not.
/// [`World::genesis`] establishes it, each slice arriving from its own
/// genesis constructor and the set empty over an empty docuverse; and
/// [`WorldState::rebuild_derived`] re-establishes it, which M2 runs over
/// every base it loads, before replay. The `Deserialize` derived below
/// establishes nothing — it leaves M7's hints empty, so every typed slice
/// reads as absent, nullification is invisible and `Active` equals `Audit`;
/// and it leaves the exception set EMPTY, so every document reads as
/// PUBLISHED — the fail-open sign PUB-7.5 names, in the one place it is
/// reachable. So a world decoded from bytes is not one until the rebuild has
/// run over it. That gate cannot be closed here: `WorldState:
/// DeserializeOwned` forces the impl to exist, and this type is public, so
/// the only defence is the discipline of the one mode that skips the rebuild
/// — `Durability::InMemory` installs the passed world as the root exactly as
/// given, and [`crate::EngineStores::new`] states the precondition for the
/// kernels built that way and what reads answer when it is violated. M7's
/// type registry is outside the hazard: it is that module's compiled format
/// constant, not carried state, so nothing about it can arrive unrebuilt.
///
/// THREE OBLIGATIONS `WorldState` places on this type that M2 cannot check,
/// each discharged by a fact about the slices rather than about this file.
/// `Clone` must be cheap, because M2 clones a world per `transact` while
/// holding the applier lock: all four slices and the exception set are `im`
/// persistent structures, so the `..self.clone()` in [`WorldState::apply`] is
/// five root clones. `Drop` must not unwind, because M2 drops the previous
/// root inside the atomic install: no type in the world's closure implements
/// a `Drop` that can panic. And this type's and [`Record`]'s `Deserialize`
/// must terminate and must not exhaust the stack on any byte string: that
/// closure holds no recursive type, so decode depth is a property of the
/// types and not of the bytes. A slice that moves to an eagerly-copied
/// collection, or grows a recursive value, breaks one of these where the
/// obligation's own text is a crate away.
#[derive(Clone, Serialize, Deserialize)]
pub struct World {
    /// The checkpoint format this layout is — first, so it is read first.
    pub(crate) format: FormatStamp,
    pub(crate) namespace: M3State,
    pub(crate) content: ContentStore,
    pub(crate) arrangement: M5State,
    pub(crate) links: LinkState,
    /// The exception set (PUB-7.5): DERIVED, never checkpointed — seeded by
    /// [`WorldState::rebuild_derived`], folded by [`WorldState::apply`] — so
    /// a decoded world holds it empty until the rebuild runs (the invariant
    /// note above).
    #[serde(skip)]
    pub(crate) drafts: Drafts,
}

/// The World checkpoint FORMAT — the version the layout of [`World`]'s bytes
/// is. The high 32 bits spell `SKPW`; the low 32 count the layouts this
/// crate has written. `1` is the layout that carries M3's publication bit
/// (2026-09-05, PUB round 1). A slice's layout change is a World layout
/// change: bump the count with it, and every older checkpoint refuses at
/// this word instead of decoding one slice's bytes as another's.
///
/// PUB-7.8: a pre-publication checkpoint MUST fail to DECODE rather than
/// resolve to everything-published. M3's own field order already makes that
/// decode fail for the slice alone (end-of-input where the bit should begin)
/// and near-certainly for the world (the bytes that follow are M4's) — this
/// stamp makes it CERTAIN. A pre-stamp checkpoint's first eight bytes are
/// M3's frontier-map length, a small count, never this word; a checkpoint
/// written by a build with a different count refuses the same way. M2's
/// fallback chain then does the rest (PUB-7.9): the next-older retained base,
/// genesis while the journal still reaches it, else `OpenError::BadCheckpoint`
/// — never a decoded world with an empty set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FormatStamp;

/// The word `FormatStamp` writes and demands back.
pub(crate) const WORLD_FORMAT: u64 = 0x534B_5057_0000_0001;

impl Serialize for FormatStamp {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(WORLD_FORMAT)
    }
}

impl<'de> Deserialize<'de> for FormatStamp {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<FormatStamp, D::Error> {
        let found = u64::deserialize(deserializer)?;
        if found == WORLD_FORMAT {
            Ok(FormatStamp)
        } else {
            Err(serde::de::Error::custom(format!(
                "world checkpoint format {found:#018x} is not this build's {WORLD_FORMAT:#018x}: \
                 a base written under another World layout — the pre-publication-bit layout \
                 above all (PUB-7.8) — must fail to decode, never default"
            )))
        }
    }
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
    /// semantics here — the folds own every decision. The one derived index
    /// the engine itself keeps rides the M3 arm: the exception set is folded
    /// beside M3's slice from M3's own answers about the record just folded
    /// (PUB-7.7's fold half — `publication::fold`), so the registration and
    /// the membership reach a reader in one snapshot.
    fn apply(&self, r: &Record) -> World {
        match r {
            Record::Namespace(x) => {
                let namespace = self.namespace.apply_m3(x);
                let drafts = publication::fold(&self.drafts, &namespace, x);
                World { namespace, drafts, ..self.clone() }
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
    /// Order: M3 → M4 → M5 → M7, the stores' dependency (DAG) order, then the
    /// engine's own derived index over M3. Why: a store's hint rebuild may
    /// only ever read slices UPSTREAM of it (a downstream read would invert
    /// the module DAG), so rebuilding in dependency order guarantees every
    /// slice a rebuild could legitimately consult is already restored; and
    /// the engine's index reads a store slice, so it comes after every store
    /// has finished with its own. As built, no STORE rebuild reads a foreign
    /// slice at all — M3 and M4 are fully serialized (M2's default identity;
    /// their docs say so), M5's `rebuild_derived` is the identity (no
    /// skip-serialized hints in v1), and M7's recomputes its hints from its
    /// OWN links map, under a registry that is a compiled constant rather
    /// than state — so the inter-store order is future-proofing, pinned here
    /// and held to by the recovery-equivalence test. The exception set's seed
    /// (PUB-7.7's seed half — `publication::seed`) reads M3's slice, which
    /// M3's identity rebuild has by then restored verbatim.
    ///
    /// Infallible by M2's trait, and fail-stop in fact: the rebuilds composed
    /// here run over state that was just DESERIALIZED, and M7's asserts what
    /// it needs of it — that every stored link key is T4-valid and
    /// element-level — as the seed asserts that every draft has an owner.
    /// With no error channel to refuse through, a base that violates any of
    /// those panics rather than returning — inside `Kernel::open`, after that
    /// checkpoint loaded, so M2's next-older-base fallback does not get its
    /// turn. A base that cannot DECODE is the other case, and the one this
    /// method never sees: `FormatStamp` and M3's own field order refuse it
    /// before any rebuild, and M2's fallback chain does get its turn.
    fn rebuild_derived(self) -> Self {
        let World { format, namespace, content, arrangement, links, drafts: _ } = self;
        // M3, then M4: neither rebuilds — both slices are fully serialized, so
        // M2's default identity is the whole of their recovery, and their
        // places in the order are held open rather than skipped.
        let arrangement = arrangement.rebuild_derived();
        let links = links.rebuild_derived();
        // Then the engine's own index, over the restored M3 slice.
        let drafts = publication::seed(&namespace);
        World { format, namespace, content, arrangement, links, drafts }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The stamp leads the encoding, and it is eight bytes of a value no
    /// pre-stamp checkpoint's first word can equal: that word is M3's
    /// frontier-map LENGTH, a count.
    #[test]
    fn the_format_stamp_leads_the_world_s_bytes() {
        let stamp = bincode::serialize(&FormatStamp).expect("a u64 serializes");
        assert_eq!(stamp, WORLD_FORMAT.to_le_bytes(), "bincode writes the word little-endian");
        let world = bincode::serialize(&World::genesis()).expect("a world serializes");
        assert!(world.starts_with(&stamp), "the stamp is the first field");
        assert_eq!(
            bincode::deserialize::<FormatStamp>(&stamp).expect("this build's word decodes"),
            FormatStamp
        );
        assert!(
            bincode::deserialize::<FormatStamp>(&(WORLD_FORMAT + 1).to_le_bytes()).is_err(),
            "any other word refuses"
        );
    }

    /// PUB-7.8, at the World: a checkpoint written without the publication
    /// bit FAILS TO DECODE — and so does one written with the bit but before
    /// the stamp. The premise is pinned first, so the hand-built shapes are
    /// the old ones and not a strawman: the current encoding IS the stamp
    /// followed by the four slices, and M3's slice at genesis IS its old
    /// bytes followed by the empty publication map's eight-byte length (M3's
    /// own test pins that half; this one rides it).
    #[test]
    fn a_checkpoint_without_the_bit_or_the_stamp_fails_to_decode() {
        let world = World::genesis();
        let current = bincode::serialize(&world).expect("a world serializes");
        let stamp = bincode::serialize(&FormatStamp).expect("a u64 serializes");

        // The pre-stamp layout (the bit present, no leading stamp): the four
        // slices alone, in order — a tuple encodes exactly as a struct does.
        let pre_stamp =
            bincode::serialize(&(&world.namespace, &world.content, &world.arrangement, &world.links))
                .expect("the slices serialize");
        assert_eq!(
            current,
            [stamp.as_slice(), pre_stamp.as_slice()].concat(),
            "the current layout is the stamp, then the old bytes"
        );
        assert!(
            bincode::deserialize::<World>(&pre_stamp).is_err(),
            "a pre-stamp checkpoint decoded — it must refuse at the stamp"
        );

        // The pre-bit layout: additionally without M3's publication map, which
        // at genesis is empty and so is the eight zero bytes that end the
        // namespace section.
        let namespace = bincode::serialize(&world.namespace).expect("M3 serializes");
        assert!(
            namespace.ends_with(&0u64.to_le_bytes()),
            "genesis's publication map is empty: an eight-byte zero length ends M3's bytes"
        );
        let mut pre_bit = pre_stamp.clone();
        pre_bit.drain(namespace.len() - 8..namespace.len());
        assert!(
            bincode::deserialize::<World>(&pre_bit).is_err(),
            "a pre-publication checkpoint decoded — it must fail, never read as everything-published"
        );

        // …and the current bytes decode, with the derived set EMPTY until the
        // rebuild runs over them — the hazard the invariant note names.
        let decoded = bincode::deserialize::<World>(&current).expect("this build's own bytes decode");
        assert_eq!(decoded.drafts().count(), 0);
    }
}
