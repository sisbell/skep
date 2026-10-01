//! The one concrete `World` and the one central `Record` enum, with the
//! `WorldState` implementation, the accessor-trait implementations, and the
//! record lifts — the Engine Composition Contract's "The engine crate
//! assembles" block, realized verbatim for the four state-contributing
//! stores (M3, M4, M5, M7) — plus the three things the assembled world
//! carries that no store does: its checkpoint FORMAT STAMP, the exception set
//! (`crate::publication`) and the grant fold (`crate::grants`). M6/M8/M9/M10
//! contribute no slice and no record variant, so nothing of theirs appears
//! here but one role impl, M10's `PublicationWorld` seam.

use std::fmt;

use serde::{Deserialize, Serialize};
use skep_address::Address;
use skep_arrangement::{HasM5, M5Rec, M5State};
use skep_content::{ContentStore, ContentWrite, HasContent};
use skep_febe::EditionClaim;
use skep_kernel::WorldState;
use skep_links::{HasLinks, LinkRec, LinkState};
use skep_namespace::{HasM3, M3Rec, M3State};

use crate::grants::{self, Grants, UniversalGrantIndexRow};
use crate::publication::{self, Drafts};

/// The ONE concrete world: every store's authoritative slice, composed
/// (contract §The engine crate assembles), each field named for the store
/// whose slice it is. Fields are crate-private — every reader OUTSIDE this
/// crate, the stores included, reaches a slice through its accessor trait
/// (contract hard rule: "Reach slices through accessor traits, never field
/// access on a concrete world"); the assembler's own code, which is all of
/// this crate, reads the fields directly.
///
/// Field ORDER is the compatibility surface, not the field names: M2
/// checkpoints a world through bincode, which encodes a struct as its fields
/// in declaration order and carries no names, so a rename is byte-neutral for
/// recovery and a reordering is not. The `FormatStamp` LEADS, and that is
/// load-bearing: it is the first thing a decoder reads, so a checkpoint BODY
/// written under any other format COUNT, or before there was one — the
/// pre-publication-bit layout above all (PUB-7.8) — is refused at byte 0 by a
/// value comparison, before any slice's bytes are read as another's. Which
/// bases reach that word at all, and what count 1's history means for the
/// rest, is `FormatStamp`'s card. The two skip-serialized fields, `drafts` and
/// `grants`, sit outside the surface: neither occupies a byte.
///
/// CANONICAL BYTES — this type's serialization IS the checkpoint body M2
/// hashes into its header (`body_hash`, which a published head names),
/// so it must be a function of the world's contents on any process and any
/// machine. The engine's part holds by construction: the stamp is a
/// constant, the four slices serialize in declaration order, and the only
/// hash-ordered structures the world holds — the exception set and the grant
/// fold — are `#[serde(skip)]`. Each slice's part is its store's (option (i),
/// stated at its own `Serialize`). A field added here joins the obligation: a
/// derived one stays skipped, and an authoritative one serializes in an order
/// that is a function of its contents. M2's golden suite holds it over this
/// type across the dev edge
/// (`two_processes_write_one_history_to_one_checkpoint_byte_string`: two
/// processes, each with its own hashers, write one history to one checkpoint
/// byte string).
///
/// INVARIANT — a world's derived state agrees with its authoritative state:
/// concretely, M7's skip-serialized hints and the engine's own two derived
/// indexes, the exception set and the grant fold. TWO construction paths
/// establish it, and the third does not.
/// [`World::genesis`] establishes it, each slice arriving from its own
/// genesis constructor and both indexes empty over a world with no draft and
/// no link; and
/// [`WorldState::rebuild_derived`] re-establishes it, which M2 runs over
/// every base it loads, before replay — at open, and again for every world
/// [`crate::Engine::world_at`] reconstructs, which is why that method states
/// the invariant as its own postcondition and why a reconstruction is
/// servable as it stands. [`WorldState::apply`] PRESERVES it: each arm folds
/// exactly the derived structures its records can move — a store's hints
/// inside that store's fold, and each engine index on the arm its doc names —
/// under the premise that doc states (no record publishes a document), so a
/// kernel whose root satisfies it satisfies it at every commit. Every
/// `Engine::check_hints` this crate's suite runs over a live engine checks
/// exactly that. The `Deserialize` derived below establishes nothing — it
/// leaves M7's hints empty, so every typed slice reads as absent, no
/// supersession edge exists, nullification is invisible and `Active` equals
/// `Audit`; it leaves the exception set EMPTY, so every document reads as
/// PUBLISHED (the fail-open sign PUB-7.5 names, in the one place it is
/// reachable); and it leaves the grant fold EMPTY, whose sign runs the OTHER
/// way (PUB-7.68), so every grant reads as ungiven. The two therefore fail in
/// opposite directions over one unrebuilt world, and no single answer looks
/// wrong. So a world decoded from bytes is not one until the rebuild has run
/// over it. That gate cannot be closed here: `WorldState: DeserializeOwned`
/// forces the impl to exist, and this type is public, so the only defence is
/// the discipline of the one mode that skips the rebuild —
/// `Durability::InMemory` installs the passed world as the root exactly as
/// given, and [`crate::EngineStores::new`] states the precondition for the
/// kernels built that way. M7's type registry is outside the hazard: it is
/// that module's compiled format constant, not carried state, so nothing
/// about it can arrive unrebuilt.
///
/// THREE OBLIGATIONS `WorldState` places on this type that M2 cannot check,
/// each discharged by a fact about the slices rather than about this file.
/// `Clone` must be cheap, because M2 clones a world per `transact` while
/// holding the applier lock: every field is `im`-persistent through and
/// through — the four slices, the exception set, and every structure the
/// grant fold holds (`Grants`' card lists them) alike — so the
/// `..self.clone()` in [`WorldState::apply`] copies a fixed handful of ROOTS
/// and no element of any collection, whatever the world holds. `Drop` must
/// not unwind, because M2 drops the previous root inside the atomic install:
/// no type in the world's closure implements a `Drop` that can panic. And
/// this type's and [`Record`]'s `Deserialize` must terminate and must not
/// exhaust the stack on any byte string, and M2 names the two shapes that
/// break that. The closure holds no RECURSIVE type, so decode depth is a
/// property of the types and not of the bytes; and no SEQUENCE in it has an
/// element that decodes from zero bytes — every element carries bytes of its
/// own, a length prefix or the byte or digit it is — so a hostile length
/// prefix runs out of input instead of spinning the decoder. A slice that
/// moves to an eagerly-copied collection, grows a recursive value, or holds a
/// sequence of zero-sized elements breaks one of these where the obligation's
/// own text is a crate away.
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
    /// The grant fold (PUB-1.31 §1, lane 3.3): the second derived index, over
    /// the LINK slice — seeded by [`WorldState::rebuild_derived`], folded by
    /// [`WorldState::apply`] on the `Links` arm, NO checkpoint slice. Empty on
    /// a decoded world until the rebuild runs, exactly as `drafts` is; its
    /// fail-open sign is the exception set's the other way (PUB-7.68 — an empty
    /// fold means an empty link map).
    #[serde(skip)]
    pub(crate) grants: Grants,
}

/// OPAQUE — the type name and nothing of the state. A world's rendering is a
/// `WorldDump` (`crate::dump`, behind its feature): deterministic,
/// byte-comparable and asked for. This is what a caller's own
/// `#[derive(Debug)]` gets for holding a world, as `Engine`'s is for holding
/// an engine, and every public type in this crate answers one.
///
/// Opaque rather than structural for a reason that is M4's and not a matter of
/// volume: `ContentStore` carries no `Debug` at all, because `Val` carries
/// none on purpose so that content blobs never render into a log. So there is
/// nothing here to derive, and writing the fields out by hand would be
/// reaching around that decision — while `namespace` and `links` would put
/// whole registries into a `dbg!`.
impl fmt::Debug for World {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("World").finish_non_exhaustive()
    }
}

/// The World checkpoint FORMAT — the version the layout of [`World`]'s bytes
/// is. The high 32 bits spell `SKPW`; the low 32 count the layouts this
/// crate has written. A slice's layout change is a World layout change: bump
/// the count with it, and every older checkpoint refuses at this word instead
/// of decoding one slice's bytes as another's. The author who changes a slice
/// is a store's, with no edge to this file, so the rule is held where it
/// meets them: `each_slice_serializes_the_fields_the_format_count_names` pins
/// every slice's top-level fields to the count, and says what it cannot see
/// below that level.
///
/// `1` has named TWO layouts: the first carries M3's publication bit
/// (2026-09-05, PUB round 1); the second appends M5's birth memo to its slice
/// (W5, 2026-09-17) under the same count. No base any build wrote in the
/// first reaches this word through a header this build loads: every one
/// carries an M2 stamp older than this build's, which M2 refuses at load by
/// name, with the owner's no-migration remedy (PUB-1.2). So the count names
/// one loadable layout, and the next World layout change bumps it. A body in
/// the first layout under a current header — which only hand-built bytes
/// produce — still fails to decode, and not by chance:
/// `a_base_written_before_the_birth_memo_fails_to_decode` states why, in the
/// encodings of M5's and M7's slices, and pins the refusal on each shape it
/// branches on, so a change beneath a slice's top level that moved the
/// misreading fails there.
///
/// PUB-7.8: a pre-publication checkpoint MUST fail to DECODE rather than
/// resolve to everything-published. Two doors hold it. M2 refuses, by its own
/// stamp, every base written under an older M2 format, which is every
/// pre-publication one; and this stamp refuses such a body under a current
/// header at its first word — a pre-stamp body opens with M3's frontier-map
/// length, a small count, never this word. So this door's own job is the one
/// M2's stamps cannot do: a World layout that moves under an unchanged M2
/// stamp, as W5's did. A checkpoint either door refuses hands M2's fallback
/// chain its turn (PUB-7.9; `OpenError::BadCheckpoint` states the chain) —
/// never a decoded world with an empty set.
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
///
/// One variant per STATE-CONTRIBUTING store — M3, M4, M5 and M7 today, with
/// M6/M8/M9/M10 contributing none — so the set grows with the decomposition,
/// which is why it is `#[non_exhaustive]`: a store that starts carrying a
/// slice adds a variant here, and `match` exhaustiveness over a public enum
/// is a promise the assembler has no reason to make to a caller that only
/// ever lifts and folds.
///
/// `Debug` is the whole of what a holder can read a record BY, and it is the
/// four stores' own: each writes its variant's account of itself, and M4's is
/// written by hand for exactly this reader — it reports a byte length where
/// the payload is, so a content blob never renders into a log. A journal
/// inspector or a harness holding a central record has no accessor to reach
/// past it, by design, since a store's record is that store's to describe.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
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
    ///
    /// TWO derived indexes ride these arms, one apiece, each on the arm whose
    /// records can move it (PUB-7.7's fold half). The EXCEPTION SET rides the
    /// M3 arm (`publication::fold`), folded beside M3's slice from M3's own
    /// answers about the record just folded, so the registration and the
    /// membership reach a reader in one snapshot. The GRANT FOLD rides the
    /// Links arm (`grants::fold`), from the deposit just folded, so a grant
    /// and the link carrying it likewise reach a reader together.
    ///
    /// NEITHER arm refolds the other's index, and for the grant fold that is
    /// a PREMISE rather than an omission. Grant admission reads the exception
    /// set, which the M3 arm moves, so an M3 record could in principle turn
    /// an unadmitted grant into an admitted one. None can: M3 writes a
    /// document's publication bit once, at the record that registers it, so
    /// the set only ever GAINS entries and no later record publishes a home
    /// that was a draft when its grant landed. That is the same
    /// time-invariance `grants::seed` rests on and states in full — a publish
    /// transition would break both halves at once, under-granting live and
    /// over-granting at the next restart.
    ///
    /// Every arm ends `..self.clone()`, which carries each unnamed field
    /// through unchanged. So a derived index added to [`World`] is folded by
    /// exactly the arms that name it here, and — because
    /// [`WorldState::rebuild_derived`] destructures rather than updates — it
    /// cannot reach a load path unanswered.
    ///
    /// TOTAL over what M2 hands it: a record a store's gate staged, or one
    /// replayed from a journal those gates wrote, folded over a world that
    /// satisfies [`World`]'s invariant. The `expect`s and the owner assertion
    /// reachable from its arms discharge facts M7's fold asserts first and
    /// M3's ops establish; over a record no gate could stage they fail-stop,
    /// and [`crate::Engine::open`] states where that lands.
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
            Record::Links(x) => {
                // The grant fold rides the Links arm, from the record just
                // folded (PUB-7.7's fold half): a `t_grant` deposit that
                // admits joins the fold, a revoking one leaves it, and the
                // registration and grant reach a reader in one snapshot. A
                // link deposit changes neither M3 nor the exception set, so
                // both are read as they stand.
                let links = self.links.apply_link(x);
                let grants = grants::fold(&self.grants, &self.namespace, &self.drafts, x);
                World { links, grants, ..self.clone() }
            }
        }
    }

    /// THE recovery order — the one place the cross-store rebuild sequence at
    /// load is stated (runs once, before replay; M2 §7).
    ///
    /// Order: M3 → M4 → M5 → M7, the stores' dependency (DAG) order, then the
    /// engine's two derived indexes — the exception set (PUB-7.7's seed half,
    /// `publication::seed`, which reads M3's slice), then the grant fold
    /// (`grants::seed`, which reads M3's slice, M7's REBUILT slice and the
    /// SEEDED exception set).
    ///
    /// The STORE half of that order is future-proofing, and no test can hold
    /// it. A store's hint rebuild may only ever read slices UPSTREAM of it (a
    /// downstream read would invert the module DAG), so dependency order is
    /// the one that stays right once a rebuild starts consulting another
    /// slice. As built none does — M3 and M4 are fully serialized (M2's
    /// default identity; their docs say so), M5's `rebuild_derived` is the
    /// identity (no skip-serialized hints in v1), and M7's recomputes its
    /// hints from its OWN links map, under a registry that is a compiled
    /// constant rather than state — so every permutation of the four recovers
    /// the same world, and no test can tell one from another.
    ///
    /// The ENGINE half is what the order rests on: two edges, each with its
    /// reason and the test that fails when it is crossed.
    ///
    /// * The grant seed runs AFTER `links.rebuild_derived()`. It enumerates
    ///   the grants class through `LinkState::type_slice`, which answers off
    ///   M7's skip-serialized typed-slice hint, and a decoded slice holds that
    ///   hint empty — so over unrebuilt links the class reads empty, the seed
    ///   admits nothing, and a restart closes every grant. Only a real load
    ///   shows it: `Engine::check_hints` rebuilds a live world's clone, whose
    ///   hints are already current, so
    ///   `the_fold_re_seeds_across_a_restart_and_an_empty_map_grants_nothing`
    ///   is the one test that fails when this edge is crossed.
    /// * The grant seed runs AFTER the exception set's, and is handed the
    ///   SEEDED set. Grant admission's published clause is a miss on that set,
    ///   and an empty one reads every home published — so the seed would
    ///   admit at load a draft-homed grant the live fold refused, and a
    ///   restart would open a private document. A load and
    ///   `Engine::check_hints` both show it, since the check's rebuild runs
    ///   this same order: `a_restart_does_not_admit_a_grant_the_live_fold_refused`
    ///   fails across a restart, and `a_grant_homed_in_a_draft_doc_1_is_inert`
    ///   fails on the check.
    ///
    /// The exception set's own seed reads M3's slice alone, which M3's
    /// identity rebuild has restored verbatim, so it has no edge beyond
    /// coming after M3.
    ///
    /// Infallible by M2's trait, and fail-stop in fact: the rebuilds composed
    /// here run over state that was just DESERIALIZED, and M7's asserts what
    /// it needs of it — that every stored link key is T4-valid and
    /// element-level — as the seed asserts that every draft has an owner.
    /// With no error channel to refuse through, a base that violates any of
    /// those panics rather than returning — inside `Kernel::open` and
    /// `Kernel::world_at` alike, after that checkpoint loaded, so M2's
    /// next-older-base fallback does not get its turn. A base that cannot
    /// LOAD is the other case, and the one this method never sees: it is
    /// refused before any rebuild — at M2's header for a base under another
    /// M2 stamp, and at `FormatStamp`'s word or later in the decode for a body
    /// in another World layout (that card states which bases reach it) — and
    /// M2's fallback chain does get its turn.
    ///
    /// COST is the two seeds', each stated at its own: `publication::seed`
    /// walks M3's documents and pays, per draft, one owner lookup —
    /// `M3State::account_seat`, ONE point lookup in the principal registry,
    /// never ω's walk of the whole of it — and `grants::seed` pays one per
    /// grant-typed link homed in a published document. So beside the three
    /// store rebuilds, which are M3's, M5's and M7's to state, this recovery
    /// is linear in the documents and the grant-typed links, up to the
    /// logarithm of each lookup, and every factor is the STORE's size rather
    /// than a caller's. A walk of Π per draft or link would make it a PRODUCT
    /// of two such sizes, each grown by one committed write, which whatever
    /// serves historical reads would pay per reconstruction it admits. This is
    /// what M2's `Kernel::world_at` means where its own cost names this method
    /// and does not size it — so a caller reading that figure for a historical
    /// reconstruction reads this one for the rest of it.
    fn rebuild_derived(self) -> Self {
        let World { format, namespace, content, arrangement, links, drafts: _, grants: _ } = self;
        // M3, then M4: neither rebuilds — both slices are fully serialized, so
        // M2's default identity is the whole of their recovery, and their
        // places in the order are held open rather than skipped.
        let arrangement = arrangement.rebuild_derived();
        let links = links.rebuild_derived();
        // Then the engine's own indexes, in dependency order: the exception
        // set over the restored M3 slice, then the grant fold, which reads the
        // rebuilt LINK slice and the exception set it stands beside (a grant is
        // admitted only when its home is a published document).
        let drafts = publication::seed(&namespace);
        let grants = grants::seed(&namespace, &links, &drafts);
        World { format, namespace, content, arrangement, links, drafts, grants }
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

// M10's two publication seams. `ReadableWorld` — the read predicate as a
// capability — forwards to one composition and sits beside it, in
// `crate::readable`. `PublicationWorld` forwards to two, and one impl block
// can sit beside only one of them, so it sits here with the World's other
// role impls.

/// M10's `PublicationWorld` seam: M10 is generic over its world and names no
/// `World`, so it reaches the two CLASS lookups its publication reads are
/// built on through this trait, off its own snapshot, and applies its own
/// rules per row. Each method forwards to the inherent read that is the real
/// one — the edition-claim lookup in `crate::editions`, the grant fold's
/// any-principal index in `crate::grants` — and neither decides anything on
/// this side of the seam.
impl skep_febe::PublicationWorld for World {
    /// The edition-claim lookup as M10's capability (lane 3.4, §2): forwards
    /// to [`World::edition_claims`], the inherent method being the real one,
    /// and M10 applies the home rule (PUB-6.13) per row.
    ///
    /// M10's `PublicationWorld` is where the contract this seam carries is
    /// stated: the two regimes the slots are judged by — OVERLAP for the `to`
    /// slot, DENOTATION for class membership — and the precondition that
    /// `target` is a registered document, which M10 checks before it asks. So
    /// through this seam `target` is ONE registered document, which bounds the
    /// caller's share of the hits and neither the store scan every call pays
    /// nor the rows a claim naming the target's account or node contributes
    /// ([`World::edition_claims`]'s COST). The inherent method stays total
    /// over every tier for a direct caller. Membership is the whole of what a
    /// row is tested for — no home, issuer or publication test runs on this
    /// side of the seam.
    fn edition_claims(&self, target: &Address) -> Vec<EditionClaim> {
        World::edition_claims(self, target)
    }

    /// The live ANY-PRINCIPAL set as M10's capability (PUB-8.47, RES-224):
    /// [`World::universal_grants`]'s rows — the STORED prefix and its issuers,
    /// the inherent read being the real one — cloned out of their borrow from
    /// the engine's [`UniversalGrantIndexRow`] into its owned twin, M10's
    /// `UniversalIndexRow`, one INDEX row for another, in the order that read
    /// hands them back. Each row is destructured whole, so a field added to
    /// the engine's row fails to compile here until this seam accounts for it.
    /// RAW, as the lookup above is: the fold-filter that narrows a served row
    /// to the prefix its issuer ω-owns (RES-231/264/273/298) is M10's own, at
    /// the read's arm, and nothing about a row's coverage is decided on this
    /// side of the seam.
    ///
    /// M10's trait promises every content prefix an admitted, unrevoked
    /// ANY-PRINCIPAL grant names, and this seam falls short of it in one shape:
    /// the fold index's shared-entry shortfall, which
    /// [`World::universal_grants`] states and
    /// `two_any_principal_grants_sharing_an_entry_are_withdrawn_together` pins
    /// through this impl. Recorded here, where M10 reads, and not decided:
    /// whether the index should count is PUB's question.
    fn universal_grant_index(&self) -> Vec<skep_febe::UniversalIndexRow> {
        World::universal_grants(self)
            .into_iter()
            .map(|UniversalGrantIndexRow { content_prefix, issuers }| {
                skep_febe::UniversalIndexRow {
                    content_prefix: content_prefix.clone(),
                    issuers: issuers.into_iter().cloned().collect(),
                }
            })
            .collect()
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
mod tests;
