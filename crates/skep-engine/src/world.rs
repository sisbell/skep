//! The one concrete `World` and the one central `Record` enum.
//!
//! Beside them stand the `WorldState` implementation, the accessor-trait
//! implementations, and the record lifts — the Engine Composition Contract's
//! "The engine crate assembles" block, realized verbatim for the four
//! state-contributing stores (M3, M4, M5, M7) — plus the four things the
//! assembled world carries that no store does: its checkpoint format stamp,
//! the identity slice (AUTH's key table and claim, `identity`), the exception
//! set (`crate::publication`) and the grant fold (`crate::grants`).
//! M6/M8/M9/M10 contribute no slice and no record variant, so nothing of
//! theirs appears here but one role impl, M10's `PublicationWorld` seam.

// The identity slice's seat: the fold hook, the slice-less resolution at
// load, the trailing field's reading, and the fold's seam over this world.
mod identity;

use std::fmt;

use serde::{Deserialize, Serialize};
use skep_address::{document_of, shift, Address, Nat};
use skep_arrangement::{HasM5, M5Rec, M5State};
use skep_content::{ContentStore, ContentStretch, ContentWrite, HasContent};
use skep_febe::EditionClaim;
use skep_identity::IdentityState;
use skep_kernel::{RebuildError, WorldState};
use skep_links::{HasLinks, LinkRec, LinkState};
use skep_namespace::{HasM3, M3Rec, M3State};

use crate::grants::{self, Grants, UniversalGrantIndexRow};
use crate::publication::{self, Drafts};

/// The one concrete world: every store's authoritative slice, composed.
///
/// It is composed per the contract (§The engine crate assembles), each field
/// named for the store whose slice it is. Fields are crate-private — every
/// reader outside this crate, the stores included, reaches a slice through
/// its accessor trait (contract hard rule: "Reach slices through accessor
/// traits, never field access on a concrete world"); the assembler's own
/// code, which is all of this crate, reads the fields directly.
///
/// Field order is the compatibility surface, not the field names: M2
/// checkpoints a world through bincode, which encodes a struct as its fields
/// in declaration order and carries no names, so a rename is byte-neutral for
/// recovery and a reordering is not. The `FormatStamp` leads, and that is
/// load-bearing: it is the first thing a decoder reads, so a checkpoint body
/// written under any other format count, or under none — the
/// pre-publication-bit layout above all (PUB-7.8) — is refused at byte 0 by a
/// value comparison, before any slice's bytes are read as another's. Which
/// bases reach that word at all, and what count 1 names for the rest, is
/// `FormatStamp`'s card. The three skip-serialized fields —
/// `identity_resolved`, `drafts` and `grants` — sit outside the surface: none
/// occupies a byte. The identity slice is the last serialized field, and that
/// is load-bearing too: a body written without it ends where it would begin,
/// which `identity::slice_or_absent` reads as `None`.
///
/// **Canonical bytes.** This type's serialization *is* the checkpoint body
/// M2 hashes into its header (`body_hash`, which a published head names), so
/// it must be a function of the world's contents on any process and any
/// machine. The engine's part holds by construction: the stamp is a
/// constant, the five slices serialize in declaration order, the identity
/// slice's maps are ordered maps keyed by address and by fingerprint
/// (AUTH-1.40's shape, which `skep-identity`'s suite pins as bytes), and the
/// only hash-ordered structures the engine's own fields hold — the exception
/// set and the grant fold — are `#[serde(skip)]`. Each slice's part is its
/// store's, stated at its own `Serialize`. A field added here joins the
/// obligation: a derived one stays skipped, and an authoritative one
/// serializes in an order that is a function of its contents. M2's golden
/// suite holds it over this type across the dev edge
/// (`two_processes_write_one_history_to_one_checkpoint_byte_string`: two
/// processes, each with its own hashers, write one history to one checkpoint
/// byte string).
///
/// **Invariant.** A world's derived state agrees with its authoritative
/// state: concretely, M7's skip-serialized hints and the engine's own two
/// derived indexes, the exception set and the grant fold. Two construction
/// paths establish it, and the third does not.
/// [`World::genesis`] establishes it, each slice arriving from its own
/// genesis constructor and both indexes empty over a world with no draft and
/// no link; and
/// [`WorldState::rebuild_derived`] re-establishes it, which M2 runs over
/// every base it loads, before replay — at open, and again for every world
/// [`crate::Engine::world_at`] reconstructs, which is why that method states
/// the invariant as its own postcondition and why a reconstruction is
/// servable as it stands. [`WorldState::apply`] preserves it: each arm folds
/// exactly the derived structures its records can move — a store's hints
/// inside that store's fold, and each engine index on the arm its doc names —
/// under the premise that doc states (no record publishes a document), so a
/// kernel whose root satisfies it satisfies it at every commit. Every
/// `Engine::check_hints` this crate's suite runs over a live engine checks
/// exactly that. The `Deserialize` derived below establishes nothing — it
/// leaves M7's hints empty, so every typed slice reads as absent, no
/// supersession edge exists, nullification is invisible, `Active` equals
/// `Audit` and `stab` — every region read and constrained descriptor —
/// matches nothing; it leaves the exception set empty, so every document reads
/// as published (the fail-open sign PUB-7.5 names, in the one place it is
/// reachable); and it leaves the grant fold empty, whose sign runs the other
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
/// **Three obligations.** They are the ones `WorldState` places on this type
/// that M2 cannot check, each discharged by a fact about the slices rather
/// than about this file. `Clone` must be cheap, because M2 clones a world per
/// `transact` while holding the applier lock: every collection in the world
/// that grows with it is `im`-persistent — the five slices', the exception
/// set's, and every one the grant fold holds (`Grants`' card lists them)
/// alike — and the rest is values that do not grow (the link slice's
/// per-slot index vector, which a link's arity bounds, and the identity
/// slice's claimant address), so the `..self.clone()` in
/// [`WorldState::apply`] copies a fixed handful of roots and small values and
/// no element of any collection that grows, whatever the world holds. `Drop`
/// must not unwind, because a world's destructor runs wherever its last
/// reference goes — the superseded root's as M2's `transact` returns, after
/// the commit, where an unwind hands the caller a panic in place of the `Ok`
/// it was owed: no type in the world's closure implements a `Drop` that can
/// panic. And this type's and [`Record`]'s `Deserialize` must terminate and
/// must not exhaust the stack on any byte string, and M2 names the two shapes
/// that break that. The closure holds no recursive type, so decode depth is a
/// property of the types and not of the bytes; and no sequence in it has an
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
    /// The identity slice (AUTH-2.79): the board's key table and claim.
    ///
    /// It is AUTH's `IdentityState`, a fold over the credential deposits of
    /// the link slice above it, stepped by [`WorldState::apply`] at each such
    /// deposit's commit (AUTH-2.80, AUTH-2.66) and checkpointed with the
    /// world, which is what lets a reopen and every historical read answer
    /// the table the live fold answered: the fold's verdicts depend on the
    /// order the deposits committed in, and the journal is the one record of
    /// that order. Authoritative in the checkpoint sense — serialized, last
    /// of the serialized fields, and never rebuilt from the deposits (no
    /// order to rebuild by) — though derived in the fold's: `None` is a
    /// checkpoint body written without the slice (by a build that writes
    /// none), or one whose slice does not decode or encodes `None`, the one
    /// case the load resolves or refuses (AUTH-2.83, AUTH-2.84) in
    /// [`WorldState::rebuild_derived`], so every loaded World carries `Some`
    /// (the post-load invariant, AUTH-2.81) and
    /// [`skep_identity::HasIdentity`] reads it through an `expect` that
    /// cannot fire. The field's serde form is AUTH-1.40's compatibility
    /// surface, which freezes with the first checkpoint a served board
    /// writes; how a body that ends before this field reads is
    /// `identity::slice_or_absent`'s, stated there.
    #[serde(default, deserialize_with = "identity::slice_or_absent")]
    pub(crate) identity: Option<IdentityState>,
    /// Whether the slice above was resolved at load rather than carried.
    ///
    /// Resolved is AUTH-2.83's case: a body without it, over a link slice
    /// holding no credential deposit, resolves to the empty table. It is a
    /// fact about the load, recorded by [`WorldState::rebuild_derived`] and
    /// carried as it is through every commit after it, read once at
    /// [`crate::Engine::open`] for the startup warning AUTH-2.86 owes the
    /// operator. Derived and skipped: it occupies no byte of the checkpoint,
    /// and a decoded world holds it `false` until the rebuild says otherwise.
    #[serde(skip)]
    pub(crate) identity_resolved: bool,
    /// The exception set (PUB-7.5): derived, never checkpointed.
    ///
    /// It is seeded by [`WorldState::rebuild_derived`] and folded by
    /// [`WorldState::apply`], so a decoded world holds it empty until the
    /// rebuild runs (the invariant note above).
    #[serde(skip)]
    pub(crate) drafts: Drafts,
    /// The grant fold (PUB-1.31): the second derived index.
    ///
    /// It is over the link slice — seeded by [`WorldState::rebuild_derived`],
    /// folded by [`WorldState::apply`] on the `Links` arm, with no checkpoint
    /// slice. Empty on a decoded world until the rebuild runs, exactly as
    /// `drafts` is; its failure sign is the exception set's the other way
    /// (PUB-7.68 — a seeded fold is empty only where no link is an admitted
    /// record of the grants class).
    #[serde(skip)]
    pub(crate) grants: Grants,
}

/// The opaque `Debug`: the type name and nothing of the state.
///
/// A world's rendering is a `WorldDump` (`crate::dump`, behind its feature):
/// deterministic, byte-comparable and asked for. This is what a caller's own
/// `#[derive(Debug)]` gets for holding a world, as `Engine`'s is for holding
/// an engine, and every public type in this crate answers one.
///
/// Opaque rather than structural for volume: the slices' own `Debug`s would
/// put every stored value (`content`, by address and byte length — `Val`
/// never renders a byte) and whole registries (`namespace`, `links`) into a
/// `dbg!`.
impl fmt::Debug for World {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("World").finish_non_exhaustive()
    }
}

/// The World checkpoint format: the version [`World`]'s byte layout is.
///
/// The high 32 bits spell `SKPW`; the low 32 are the layout count, and `1`
/// names every layout this crate has written (below). A slice's layout change
/// is a World layout change: bump the count with it, and every older
/// checkpoint refuses at this word instead of decoding one slice's bytes as
/// another's. The author who changes a slice is a store's, with no edge to
/// this file, so the rule is held where it meets them:
/// `each_slice_serializes_the_fields_the_format_count_names` pins every
/// slice's top-level fields to the count, and says what it cannot see below
/// that level.
///
/// `1` names six layouts, each the one before it with one change: the first
/// carries M3's publication bit; the second appends M5's birth memo to its
/// slice, and the third the shot terms after it; the fourth appends the
/// identity slice after M7's (AUTH-2.79); the fifth holds each of M4's
/// entries as a value or a stretch — a tagged enum where a bare value stood —
/// and gains the stretch record, [`Record::ContentStretch`]; and the sixth
/// appends the fork sources to the arrangement slice. They stand under one
/// count because no served board exists and the dev boards are re-seeded,
/// the kernel's golden regenerated under the current stamps. No base any
/// build wrote in the first reaches this word through a header this build
/// loads: every one carries an M2 stamp older than this build's, which M2
/// refuses at load by name, with the no-migration remedy (PUB-1.2). A body in
/// a later layout but the sixth, under a current header, does reach the
/// decoder and is not refused at this word, and each change it predates
/// meets it further in. A body whose content entries are bare values fails at
/// its first such entry, whose value's length prefix reads as an entry tag no
/// variant or an overlong stretch (skep-content's suite pins both shapes);
/// one that passes its content map — an empty one, or one of tagged entries
/// — meets the arrangement slice short of its fork sources, which carry no
/// default; and the board then opens from genesis where its journal still
/// reaches it, replaying its per-byte frames into one-byte values the readers
/// serve as they serve any value. A body that ends where the identity slice
/// would begin reads as `identity: None` (`World`'s field states the
/// reading), and is resolved or refused at load by AUTH-2.83's rule rather
/// than defaulted into a table — the one layout change this count names
/// whose old bodies the spec gives a reading, though a slice-less body from
/// any build meets the content and arrangement changes first. So the count
/// names layouts beside the current one whose bodies reach the decoder, and
/// the next World layout change bumps it. A body in the first layout under a
/// current header — which only hand-built bytes produce — still fails to
/// decode, and not by chance:
/// `a_base_written_before_the_birth_memo_fails_to_decode` states why, in the
/// encodings of M5's and M7's slices, and pins the refusal on each shape it
/// branches on, so a change beneath a slice's top level that moved the
/// misreading fails there.
///
/// PUB-7.8: a pre-publication checkpoint must fail to decode rather than
/// resolve to everything-published. Two doors hold it. M2 refuses, by its own
/// stamp, every base written under an older M2 format, which is every
/// pre-publication one; and this stamp refuses such a body under a current
/// header at its first word — a pre-stamp body opens with M3's frontier-map
/// length, a small count, never this word. So this door's own job is the one
/// M2's stamps cannot do: a World layout that moves under an M2 stamp that
/// does not. A checkpoint either door refuses hands M2's fallback chain its
/// turn (PUB-7.9; `OpenError::BadCheckpoint` states the chain) — never a
/// decoded world with an empty set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FormatStamp;

/// The World's format stamp: the word `FormatStamp` writes and demands back.
///
/// It stands at the head of every checkpoint body. Public for the one caller
/// above that names it, the daemon's version line, which renders it as the
/// refusal below does (`{:#018x}`); re-exported at the crate root.
pub const WORLD_FORMAT: u64 = 0x534B_5057_0000_0001;

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

/// The one central record enum: one variant per store record type.
///
/// It is the contract's (§The engine crate assembles), each variant named for
/// the store whose delta it carries.
///
/// Two store crates name their own slice and record types by module ordinal
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
/// invariant survives assembly). Variant order carries the same bincode
/// obligation as `World`'s fields: variants encode by index, so a rename is
/// byte-neutral for replay and a reordering is not.
///
/// One variant per record kind of each state-contributing store — M3, M4, M5
/// and M7, M4 carrying two kinds, with M6/M8/M9/M10 contributing none — so
/// the set grows with the decomposition, which is why it is
/// `#[non_exhaustive]`: a store that starts carrying a slice, or a second
/// record kind, adds a variant here — appended, as the fifth is — and
/// `match` exhaustiveness over a public enum is a promise the assembler has
/// no reason to make to a caller that only ever lifts and folds.
///
/// `Debug` is the whole of what a holder can read a record by, and it is the
/// four stores' own: each gives its variant's account of itself, and M4's
/// two report a byte length where the value or the stretch is (`Val`'s own
/// `Debug`, and `ContentStretch`'s), so a content blob never renders into a
/// log. A journal inspector or a harness holding a central record has no
/// accessor to reach past it, by design, since a store's record is that
/// store's to describe.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Record {
    /// The namespace store's record, folded into the `namespace` slice.
    Namespace(M3Rec),
    /// The content store's value record, folded into the `content` slice.
    Content(ContentWrite),
    /// The arrangement store's record, folded into the `arrangement` slice.
    Arrangement(M5Rec),
    /// The link store's record, folded into the `links` slice.
    Links(LinkRec),
    /// M4's second record kind: a run of single-byte values held as one record.
    ///
    /// The run is of consecutive single-byte values written by one insert or
    /// one publish shot, held as one record and one map entry, folded by
    /// [`ContentStore::apply_stretch`]. Index 4, appended after `Links`, so
    /// the other four keep the indexes a journal written without it encodes
    /// them by.
    ContentStretch(ContentStretch),
}

/// Returns whether `stretch` lies within its document's content frontier.
///
/// The frontier is the content chain's, in `namespace` — the second site of
/// the one-number check M5's staging step makes (`a range mint and its
/// stretch carry one number`): the fold sees M3's slice and M4's together,
/// live and on replay, the one place a record decoded from bytes is held to
/// the chain. The stretch's reach, `first ⊕ len`, is at or below the next
/// address the chain would mint — `ordinal(first) + len − 1 ≤ the frontier`.
/// A home M3 never registered, or a key with no document, has no frontier to
/// hold the stretch to and is not judged here: the mint path never issues
/// one, and a release build's mis-routed key is the store card's own warning.
fn stretch_within_frontier(namespace: &M3State, stretch: &ContentStretch) -> bool {
    let Some(home) = document_of(stretch.addr()) else { return true };
    let Some(next) = namespace.next_content_address(&home) else { return true };
    shift(stretch.addr().tumbler(), &Nat::from(stretch.len())) <= *next.tumbler()
}

impl WorldState for World {
    type Record = Record;

    /// Folds `r` into this world: the one fold step (M2's `apply` obligation).
    ///
    /// It dispatches each variant into its store's own pure/total/deterministic
    /// fold, replacing that store's slice and the engine state that rides its
    /// arm (below; contract §The engine crate assembles). No semantics here —
    /// the folds own every decision.
    ///
    /// Two derived indexes ride these arms, one apiece, each on the arm whose
    /// records can move it (PUB-7.7's fold half). The exception set rides the
    /// M3 arm (`publication::fold`), folded beside M3's slice from M3's own
    /// answers about the record just folded, so the registration and the
    /// membership reach a reader in one snapshot. The grant fold rides the
    /// Links arm (`grants::fold`), from the deposit just folded, so a grant
    /// and the link carrying it likewise reach a reader together.
    ///
    /// Neither arm refolds the other's index, and for the grant fold that is
    /// a premise rather than an omission. Grant admission reads the exception
    /// set, which the M3 arm moves, so an M3 record could in principle turn
    /// an unadmitted grant into an admitted one. None can: M3 writes a
    /// document's publication bit once, at the record that registers it, so
    /// the set only ever gains entries and no later record publishes a home
    /// that was a draft when its grant landed. That is the same
    /// time-invariance `grants::seed` rests on and states in full — a publish
    /// transition would break both halves at once, under-granting live and
    /// over-granting at the next restart.
    ///
    /// The identity slice rides the Links arm too, after the link and the
    /// grant fold have landed (AUTH-2.80): `identity::fold` steps the slice
    /// from the deposit just folded, over this post-deposit world as the
    /// fold's ctx — so the record bytes the deposit names, the home's owner
    /// and account-hood and its birth state are read as of this very commit
    /// (AUTH-2.66's "evaluated at the deposit's commit"), live and on every
    /// replay alike — with the two fast exits that leave every non-credential
    /// deposit, which is nearly every link, un-folded at the cost of an arity
    /// test and at most three span comparisons.
    ///
    /// Every arm ends `..self.clone()`, which carries each unnamed field
    /// through as it is. So a derived index added to [`World`] is folded by
    /// exactly the arms that name it here, and — because
    /// [`WorldState::rebuild_derived`] destructures rather than updates — it
    /// cannot reach a load path unanswered.
    ///
    /// Total over what M2 hands it: a record a store's gate staged, or one
    /// replayed from a journal those gates wrote, folded over a world that
    /// satisfies [`World`]'s invariant.
    ///
    /// # Panics
    ///
    /// Panics over a record no gate could stage, where the `expect`s and the
    /// owner assertion reachable from its arms fail: they discharge facts
    /// M7's fold asserts first and M3's ops establish, and
    /// [`crate::Engine::open`] states where that lands. A debug build also
    /// fail-stops on a content stretch past its document's content frontier
    /// (`stretch_within_frontier`), and where the identity hook asserts
    /// (`identity::fold` states where).
    fn apply(&self, r: &Record) -> World {
        match r {
            Record::Namespace(x) => {
                let namespace = self.namespace.apply_m3(x);
                let drafts = publication::fold(&self.drafts, &namespace, x);
                World { namespace, drafts, ..self.clone() }
            }
            Record::Content(x) => World { content: self.content.apply_write(x), ..self.clone() },
            Record::ContentStretch(x) => {
                // The fold-side check of the one number two records carry
                // (`stretch_within_frontier`): a debug build fail-stops on a
                // stretch past its chain's frontier; a release build folds
                // it, the fold staying total and silent as M2 asks of
                // `apply` — the wedge it would leave is the staging site's to
                // refuse, and this site's to name.
                debug_assert!(
                    stretch_within_frontier(&self.namespace, x),
                    "a content stretch reaches past its document's content frontier: the range \
                     minted and the stretch written carry two numbers"
                );
                World { content: self.content.apply_stretch(x), ..self.clone() }
            }
            Record::Arrangement(x) => {
                World { arrangement: self.arrangement.apply_m5(x), ..self.clone() }
            }
            Record::Links(x) => {
                // The grant fold rides the Links arm, from the record just
                // folded (PUB-7.7's fold half): a `t_grant` deposit that
                // admits joins the fold, a revoking one withdraws the grant
                // it names, a `t_replaces` pair re-decides the grant it
                // follows, and the link and the grant it carries reach a
                // reader in one snapshot. A link deposit changes neither M3
                // nor the exception set, so both are read as they stand.
                // Then the identity slice's step, over the world the deposit
                // has just entered (AUTH-2.80) — the one place a commit moves
                // the slice.
                let links = self.links.apply_link(x);
                let grants = grants::fold(&self.grants, &self.namespace, &self.drafts, x);
                identity::fold(World { links, grants, ..self.clone() }, x)
            }
        }
    }

    /// Rebuilds the derived state at load: the one statement of the order.
    ///
    /// It is the recovery order — the one place the cross-store rebuild
    /// sequence at load is stated (it runs once, before replay; M2 §7).
    ///
    /// Order: M3 → M4 → M5 → M7, the stores' dependency (DAG) order, then the
    /// engine's two derived indexes — the exception set (PUB-7.7's seed half,
    /// `publication::seed`, which reads M3's slice), then the grant fold
    /// (`grants::seed`, which reads M3's slice, M7's rebuilt slice and the
    /// seeded exception set).
    ///
    /// The store half of that order is future-proofing, and no test can hold
    /// it. A store's hint rebuild may only ever read slices upstream of it (a
    /// downstream read would invert the module DAG), so dependency order is
    /// the one that stays right once a rebuild starts consulting another
    /// slice. As built none does — M3 and M4 are fully serialized (M2's
    /// default identity; their docs say so), M5's `rebuild_derived` is the
    /// identity (no skip-serialized hints in v1), and M7's recomputes its
    /// hints from its own links map, under a registry that is a compiled
    /// constant rather than state — so every permutation of the four recovers
    /// the same world, and no test can tell one from another.
    ///
    /// The engine half is what the order rests on: two edges, each with its
    /// reason and the test that fails when it is crossed.
    ///
    /// * The grant seed runs after `links.rebuild_derived()`. It enumerates
    ///   the grants class through `LinkState::type_slice`, which answers off
    ///   M7's skip-serialized typed-slice hint, and a decoded slice holds that
    ///   hint empty — so over unrebuilt links the class reads empty, the seed
    ///   admits nothing, and a restart closes every grant. Only a real load
    ///   shows it: `Engine::check_hints` rebuilds a live world's clone, whose
    ///   hints are already current, so the tests that fail when this edge is
    ///   crossed are the ones that load a base holding a grant —
    ///   `the_fold_re_seeds_across_a_restart_and_an_empty_map_grants_nothing`
    ///   among them.
    /// * The grant seed runs after the exception set's, and is handed the
    ///   seeded set. Grant admission's published clause is a miss on that set,
    ///   and an empty one reads every home published — so the seed would
    ///   admit at load a draft-homed grant the live fold refused, and a
    ///   restart would open a private document. A load and
    ///   `Engine::check_hints` both show it, since the check's rebuild runs
    ///   this same order:
    ///   `a_restart_does_not_admit_a_grant_the_live_fold_refused` fails
    ///   across a restart, and `a_grant_homed_in_a_draft_doc_1_is_inert`
    ///   fails on the check.
    ///
    /// The exception set's own seed reads M3's slice alone, which M3's
    /// identity rebuild has restored verbatim, so it has no edge beyond
    /// coming after M3.
    ///
    /// Then the identity slice's resolution (AUTH-2.83), last and after M7's
    /// rebuild — `identity::resolve`, which reads the rebuilt link slice and
    /// nothing else: a body that carried the slice keeps it; a body that did
    /// not, over a link slice holding no credential deposit, resolves to the
    /// empty table (the fold over no credential deposit *is* the genesis
    /// table, so nothing is guessed); and one holding any such deposit is
    /// refused (below). The order is a correctness pin too: the candidates
    /// come from `match_links`, which answers off M7's skip-serialized
    /// coverage index, empty until `links.rebuild_derived()` has run — over
    /// unrebuilt links the resolution finds no credential deposit and
    /// resolves a slice-less body that holds some to the empty table, and
    /// `the_load_steps_back_from_a_slice_less_checkpoint_and_replays_the_true_table`
    /// fails when that edge is crossed.
    ///
    /// **Cost.** It is the two seeds', each stated at its own, and the
    /// identity slice's resolution where a body carried no slice:
    /// `publication::seed` walks M3's documents and pays, per draft, one owner
    /// lookup — `M3State::account_seat`, one point lookup in the principal
    /// registry, never ω's walk of the whole of it — `grants::seed` pays one
    /// per grant-typed link homed in a published document, and
    /// `identity::resolve` asks the link slice's coverage index once per
    /// credential type and reads each candidate's type slot until one is
    /// recognized. So beside the two store rebuilds, which are M5's and M7's
    /// to state (M3's slice takes none), this recovery is linear in the
    /// documents, the grant-typed links and those candidates, up to the
    /// logarithm of each lookup, and every factor is the store's size rather
    /// than a caller's. A walk of Π per draft or link would make it a product
    /// of two such sizes, each grown by one committed write, which whatever
    /// serves historical reads would pay per reconstruction it admits. This
    /// is what M2's `Kernel::world_at` means where its own cost names this
    /// method and does not size it — so a caller reading that figure for a
    /// historical reconstruction reads this one for the rest of it.
    ///
    /// # Errors
    ///
    /// Fallible by M2's trait on the identity arm (the AUTH spec's seam
    /// delta, AUTH-2.85): a body that carried no slice, over a link slice
    /// holding any credential deposit, is refused — the one `Err` this method
    /// answers, M2's own `RebuildError`, which makes the base not a start
    /// point (AUTH-2.84) and hands M2's fallback chain its turn, at
    /// `Kernel::open` and at every `Kernel::world_at` alike.
    ///
    /// # Panics
    ///
    /// Panics, fail-stop, on every other arm: the store rebuilds composed here
    /// run over state that was just deserialized, and M7's asserts what it
    /// needs of it — that every stored link key is T4-valid and element-level,
    /// and that every slot its fold classifies is level-uniform — as the seed
    /// asserts that every draft has an owner. With no error channel for those,
    /// a base that violates any of them panics rather than returning — inside
    /// `Kernel::open` and `Kernel::world_at` alike, after that checkpoint
    /// loaded, so M2's next-older-base fallback does not get its turn. A base
    /// that cannot load is the other case, and the one this method never sees:
    /// it is refused before any rebuild — at M2's header for a base under
    /// another M2 stamp, and at `FormatStamp`'s word or later in the decode
    /// for a body in another World layout (that card states which bases reach
    /// it) — and M2's fallback chain does get its turn.
    fn rebuild_derived(self) -> Result<Self, RebuildError> {
        let World {
            format,
            namespace,
            content,
            arrangement,
            links,
            identity,
            identity_resolved: _,
            drafts: _,
            grants: _,
        } = self;
        // M3, then M4: neither rebuilds — both slices are fully serialized, so
        // M2's default identity is the whole of their recovery, and their
        // places in the order are held open rather than skipped.
        let arrangement = arrangement.rebuild_derived();
        let links = links.rebuild_derived();
        // Then the engine's own indexes, in dependency order: the exception
        // set over the restored M3 slice, then the grant fold, which reads the
        // rebuilt link slice and the exception set it stands beside (a grant is
        // admitted only when its home is a published document).
        let drafts = publication::seed(&namespace);
        let grants = grants::seed(&namespace, &links, &drafts);
        // Last, the identity slice: carried, resolved, or refused (AUTH-2.83).
        let (identity, identity_resolved) = identity::resolve(identity, &links)?;
        Ok(World {
            format,
            namespace,
            content,
            arrangement,
            links,
            identity: Some(identity),
            identity_resolved,
            drafts,
            grants,
        })
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

/// M10's `PublicationWorld` seam: the two class lookups its reads are built on.
///
/// M10 is generic over its world and names no `World`, so it reaches the two
/// class lookups its publication reads are built on through this trait, off
/// its own snapshot, and applies its own rules per row. Each method forwards
/// to the inherent read that is the real one — the edition-claim lookup in
/// `crate::editions`, the grant fold's any-principal index in
/// `crate::grants` — and neither decides anything on this side of the seam.
impl skep_febe::PublicationWorld for World {
    /// Returns the edition-claim lookup as M10's capability.
    ///
    /// It forwards to [`World::edition_claims`], the inherent method being the
    /// real one, and M10 applies the home rule (PUB-6.13) per row.
    ///
    /// M10's `PublicationWorld` is where the contract this seam carries is
    /// stated: the two regimes the slots are judged by — overlap for the `to`
    /// slot, denotation for class membership — and the precondition that
    /// `target` is a registered document, which M10 checks before it asks. So
    /// through this seam `target` is one registered document, which bounds the
    /// caller's share of the hits and not the rows a claim naming the target's
    /// account or node contributes ([`World::edition_claims`]'s cost). The
    /// inherent method stays total over every tier for a direct caller.
    /// Membership and supersession are the whole of what a row is tested for
    /// — no home, issuer or publication test runs on this side of the seam.
    ///
    /// # Panics
    ///
    /// Panics where [`World::edition_claims`] does: on a store that breaks the
    /// link store's own postconditions.
    fn edition_claims(&self, target: &Address) -> Vec<EditionClaim> {
        World::edition_claims(self, target)
    }

    /// Returns the live any-principal set as M10's capability (PUB-8.47).
    ///
    /// It is [`World::universal_grants`]'s rows (RES-224) — the stored prefix
    /// and its issuers, the inherent read being the real one — cloned out of
    /// their borrow from the engine's [`UniversalGrantIndexRow`] into its
    /// owned twin, M10's `UniversalIndexRow`, one index row for another, in
    /// the order that read hands them back. Each row is destructured whole,
    /// so a field added to the engine's row fails to compile here until this
    /// seam accounts for it. Raw, as the lookup above is: the fold-filter that
    /// narrows a served row to the prefix its issuer ω-owns
    /// (RES-231/264/273/298) is M10's own, at the read's arm, and nothing
    /// about a row's coverage is decided on this side of the seam.
    ///
    /// M10's trait promises every content prefix an admitted, unrevoked
    /// any-principal grant names, and this seam keeps that promise: the fold
    /// honors one grant per (issuer, prefix) key at a time, so no two
    /// operative grants share an index entry and revoking one leaves no
    /// survivor unlisted, which
    /// `a_duplicate_any_principal_grant_shares_no_universal_entry` pins
    /// through this impl. Stated here, where M10 reads: the index holds no
    /// count and needs none (`crate::grants` states why).
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
// their own record type and the caller lifts with `.into()` (contract hard
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

impl From<ContentStretch> for Record {
    fn from(r: ContentStretch) -> Record {
        Record::ContentStretch(r)
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
