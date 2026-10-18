//! M5's `WorldState` slice, its journal delta and the fold (§A / §3–§8 folds).
//!
//! It holds the slice ([`M5State`]), one document's arrangement and the
//! absent-⇒-empty convention every read of the map goes through
//! ([`M5State::arrangement_of`]), the sole journal delta ([`M5Rec`]), and the
//! pure fold ([`M5State::apply_m5`]), which reaches an arrangement through
//! this file's own accessors and calls nothing `reads.rs` or `shot.rs`
//! defines.

use std::sync::LazyLock;

use num_traits::One;
use serde::{Deserialize, Serialize};
use skep_address::{content_subspace, link_subspace, Address, Nat};

use crate::chain::is_birth_version;
use crate::decode::entry_by_entry;
use crate::provenance::Provenance;
use crate::run::Run;
use crate::run_list::RunList;

/// One document's POOM: the content and link run-lists (§Core data model).
///
/// Exactly these two subspaces exist, which is a fact about the arrangement
/// and so is answered by [`list`](DocArrangement::list) rather than restated
/// by each read that routes on a subspace numeral. The two lists are private
/// to this module: a read reaches one through `list` or through
/// [`M5State::content_list`]/[`M5State::link_list`], and only the fold
/// replaces one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DocArrangement {
    content: RunList,
    link: RunList,
}

impl DocArrangement {
    /// Returns the run-list `subspace` selects; `None` when it names neither.
    ///
    /// `s_C` and `s_L` (M1's numerals) are the only two that exist. Every
    /// subspace-routed read folds that `None` to its own empty answer.
    pub(crate) fn list(&self, subspace: &Nat) -> Option<&RunList> {
        if *subspace == content_subspace() {
            Some(&self.content)
        } else if *subspace == link_subspace() {
            Some(&self.link)
        } else {
            None
        }
    }
}

/// The arrangement an absent document reads as.
///
/// It is the lazy convention stated on [`M5State`], made a value so
/// [`M5State::arrangement_of`] can hand back a borrow on either branch.
/// Once-only initialization of a `Default`.
static EMPTY_ARRANGEMENT: LazyLock<DocArrangement> = LazyLock::new(DocArrangement::default);

/// Authoritative folded state: the per-document POOM and R beside it.
///
/// R is the provenance relation (`Provenance`), co-located with the POOM
/// (ASN-0075). The arrangement is authoritative mutable state recovered by
/// replay — not a recomputable hint (ASN-0047 P3); provenance is the
/// append-only history housed next to it, and it is a type of its own whose
/// methods offer no removal, so the permanence R promises holds by
/// construction. The arrangement map is sparse: an absent doc reads as the
/// empty arrangement (the eager-lazy split with M3). v1 has no derived-hint
/// fields ⇒ [`rebuild_derived`](M5State::rebuild_derived) is the identity.
///
/// **The birth extents** (`birth_extents`; PUB-3.19 as RES-276 reads it,
/// frozen by R2-kickoff D2) are the third field, and the one that is derived:
/// per birth version — a trunk's opening member `D.1` — the content count
/// that version was born with, which [`birth_extent`](M5State::birth_extent)
/// answers and the doc-metadata read serves. They have no record of their
/// own and no op writes them: the fold notes each off the record that mints
/// the version — the shot's [`ShotPlace`](M5Rec::ShotPlace), or the snapshot
/// an owned VERSION stages — so replay re-derives them from the journal as it
/// stands and the journal carries nothing for them. They are not a
/// recomputable hint all the same, which is why the checkpoint carries them
/// and `rebuild_derived` has nothing to seed: while a birth version is the
/// head a declared deposit appends to its arrangement (PUB-2.66), the
/// run-list merges an I-adjacent deposit into the last birth run, and R keeps
/// spans and no record boundary, so nothing the arrangement holds afterwards
/// says where the birth content ended. Nothing reads them to decide a write.
///
/// **The shot terms** (`shot_terms`; signed-ops D25) are the fourth field,
/// and the one that is journaled per member: for every version member the
/// shot minted, the two client terms of that shot which nothing else the fold
/// keeps answers — the count the client placed (Σ width of its runs,
/// `placed`) and the base's extent the staged copy took (`base_extent`), an
/// option whose absence is the birth bit — the birth shape's: a first shot
/// with `base` absent, where the count is `birth_extent(D.1)`; a birth version
/// minted off its memberless document as its base carries `Some` of the
/// extent that copy took, and its birth extent counts the tail carried past
/// it. They ride the shot's own placing record
/// ([`ShotPlace`](M5Rec::ShotPlace)), so they are hashed into the commit
/// chain, folded here, carried by every checkpoint, replayed on every replica
/// and read off the live snapshot by anyone holding the member's address
/// ([`shot_terms`](M5State::shot_terms)) — which is what a verifier of the
/// shot's entry signature needs beyond the member's own runs: the signature
/// binds the runs the client placed in the address form, `placed` says where
/// they end and the base's carried tail begins, `base_extent` is in the
/// signed bytes, and `base` itself is derived from the member's address. The
/// run-list erases the boundary between the client's last run and the carried
/// tail whenever the two are I-adjacent, so nothing the arrangement holds
/// afterwards could re-derive `placed`. Nothing reads them to decide a write.
///
/// **The fork sources** (`fork_sources`; the fork-source design record) are
/// the fifth field, and the one that is noted off a record already
/// journaled: for every document a `version` minted — an owned member and a
/// cross-owner fork alike — the source it was born sharing, the
/// [`VersionSnapshot`](M5Rec::VersionSnapshot)'s `source`: the reading
/// surface the op resolved, a version member where the source had a chain,
/// the bare document otherwise. The record carries the fact and the fold
/// shares the arrangement it names, but in the journal alone the address
/// would not survive the reclaim floor. Noted here it is what every other
/// fact of a member's minting is — carried whole by every checkpoint,
/// answered the same at every position by
/// [`fork_source`](M5State::fork_source), which the doc-metadata read serves
/// as `source` to every reader of the fork and a merge takes as a cross-owner
/// fork's base. Nothing reads them to decide a write.
///
/// **Class invariants**, relating the fields. The reads state what they
/// answer; these are what makes those answers mean it.
///
/// * **R is append-only.** Structural: `Provenance` offers `append` and
///   reads, and no removal, so no fold arm can shorten any document's R↾doc
///   however the variant set grows (ASN-0047 P2).
/// * **P4★ — present containment is recorded.** For every `doc`, the current
///   content image `⋃ r.iextent()` over `content_runs(doc)` is contained in
///   `provenance.ever_contained(doc)`. Established by the three arms that
///   place: [`ContentPlace`](M5Rec::ContentPlace) appends exactly the
///   iextents it splices in, [`ShotPlace`](M5Rec::ShotPlace) exactly the
///   iextents of the runs it splices at ordinal 1 (none when it places none),
///   and [`VersionSnapshot`](M5Rec::VersionSnapshot) exactly the iextents of
///   the run-list it installs. Preserved by the other three:
///   [`ContentRemove`](M5Rec::ContentRemove) only contracts the image,
///   [`ContentReorder`](M5Rec::ContentReorder) permutes the same arranged
///   addresses, and [`LinkSeat`](M5Rec::LinkSeat) touches the link
///   run-list, which is no part of the content image. Splitting and
///   coalescing move the boundaries between runs and not the addresses they
///   cover, so the image is stable under both. On the decode path P4★ is
///   M2's integrity, not the type's: a checkpoint carries both fields whole
///   and no door re-establishes their relation — unlike R's span shape and
///   the run-list's maximal merge, whose serde doors do — because
///   containment costs a per-class set difference over every document's
///   R↾doc at every load. A decoded state violating it faults nothing: it
///   answers `docs_ever_containing` with false negatives at once, and
///   `deletions` omits whatever unrecorded address the next delete removes.
/// * **D-SEQ★ — each subspace's arranged positions are the dense prefix.**
///   For every `doc` and each subspace `s`, the positions the arrangement
///   binds are exactly `{[s, k] : 1 ≤ k ≤ n_s}` — anchored at ordinal 1, no
///   holes. Structural rather than maintained: a run-list stores no
///   V-positions, so a run's V-start is a prefix sum (§1; ASN-0047 D-SEQ★, via
///   contiguity D-CTG★ and minimum-position D-MIN★), and no fold arm can open
///   a gap because there is nothing in which to open one.
/// * **BIRTH★ — a birth version's extent is noted once, by its mint, and
///   never moved.** `birth_extents` gains `m`'s entry at the record that
///   mints `m` — [`ShotPlace`](M5Rec::ShotPlace), which the shot journals
///   for every member it mints, an empty placement included, or
///   [`VersionSnapshot`](M5Rec::VersionSnapshot), a snapshot of an empty
///   source noting zero — and at no other: a
///   [`ContentPlace`](M5Rec::ContentPlace) mints nothing and notes nothing,
///   so a deposit that grows the head grows `content_count(m)` and not
///   `birth_extent(m)` once `m` is minted; a `ShotPlace` minting `m` after a
///   `ContentPlace` naming it, an order no op stages, counts that placement's
///   positions in the extent. On the op path the extent `e` noted for `m` is
///   at most `content_count(m)`, and positions `[1, e]` of `m` are the
///   arrangement it was minted with: a published member admits no removal
///   and no re-arrangement (PUB-2.11), and a deposit lands past the arranged
///   extent. On the decode path BIRTH★ is M2's integrity, as P4★ is: a
///   checkpoint carries `birth_extents` whole, and no door re-establishes
///   that each key is a birth version or each count its mint's. A decoded
///   state violating it faults nothing — no read does arithmetic on an
///   extent, and [`birth_extent`](M5State::birth_extent) answers the count
///   carried — but a consumer that takes the key set for version members, as
///   the engine's dump filter does, trusts the checkpoint for it.
/// * **TERMS★ — a member's shot terms are the terms of the shot that minted
///   it.** `shot_terms` gains `m`'s entry at `m`'s own
///   [`ShotPlace`](M5Rec::ShotPlace), the record the commit that minted `m`
///   pushed, and no other record on the op path names `m` there: a member is
///   minted once, and the shot is the one op that mints a member with a
///   placement of its own. So `placed(m)` is a prefix of the arrangement `m`
///   was minted with — positions `[1, placed(m)]` are the client's runs and
///   `(placed(m), birth_extent(m)]` (or the count at the mint, for a later
///   member) the base's carried tail — and
///   [`address_form_of`](M5State::address_form_of) reads that prefix back.
///   On the decode path, as BIRTH★: carried whole, re-established by no
///   door.
/// * **SOURCE★ — a document's fork source is the source of the `version`
///   that minted it, noted once and never moved.** `fork_sources` gains
///   `new`'s entry at `new`'s own [`VersionSnapshot`](M5Rec::VersionSnapshot)
///   — on both branches of that arm, an empty surface included, since the
///   fact is the source and not the content shared — and at no other record:
///   a [`ShotPlace`](M5Rec::ShotPlace) mints a member off no source and notes
///   none, a placement mints nothing, and a `fork`'s mint reaches this slice
///   with no record at all. A `version`-minted document is minted once, so
///   its entry is written once; `source` is the surface that record named at
///   its commit position and no later state of the source moves it. So
///   [`fork_source`](M5State::fork_source) answers exactly the documents a
///   `version` minted — an owned member and a cross-owner fork alike — and
///   `None` for every other address: a trunk no `version` minted, a shot
///   member, a `fork`-minted or created document. A fork of a fork answers
///   its own source and no further: one hop, the fact as journaled. On the
///   decode path, as BIRTH★: carried whole, re-established by no door — and
///   a checkpoint written without the field fails to decode rather than
///   answering `None` for a fork, the map carrying no default (the engine's
///   World door states the rule).
///
/// Two public reads mean what they say only under P4★:
/// [`deletions`](M5State::deletions) is the deleted set rather than an
/// arbitrary difference, and
/// [`docs_ever_containing`](M5State::docs_ever_containing) is a superset with
/// no false negatives — the property that makes narrowing it by
/// [`arranges_any`](M5State::arranges_any) sound.
///
/// Three things a caller may rely on under D-SEQ★, each restated where it is
/// answered so a reader need not come here for it:
///
/// * [`point`](M5State::point) answers `Some` at `[s, k]` exactly for
///   `1 ≤ k ≤ n_s` — the arranged positions are an interval, so one bound
///   settles membership;
/// * [`content_count`](M5State::content_count) is both the width sum of
///   [`content_runs`](M5State::content_runs) and the largest arranged content
///   ordinal, and
///   [`link_count`](M5State::link_count)/[`link_runs`](M5State::link_runs)
///   likewise — a count, not a total that some hole might over-report;
/// * the runs [`resolve`](M5State::resolve) hands back tile V contiguously,
///   so a caller that needs their V-starts accumulates widths instead of
///   locating each run again.
///
/// **Every read here answers the address named.** `resolve`, `iter_resolve`,
/// `point`, `content_runs`, `link_runs`, `content_count`, `link_count`,
/// `content_run_count`, `link_run_count`, `project`, `arranges_any`,
/// `deletions` and `recorded_span_count` never float: asked of a bare
/// published document with members, they answer its own pre-chain
/// arrangement, which the chain has superseded, and its own R↾doc, not the
/// trunk head's. Head-float (PUB-2.49) is a composition the reader makes —
/// [`reading_surface`](crate::reading_surface) first, then the read — as
/// M6's and M8's arrangement readers do.
/// [`birth_extent`](M5State::birth_extent) answers the address named as
/// well: asked of a bare document it answers `None` — the document is no
/// birth version — and never its `D.1`'s extent.
///
/// Every field keys by the document `Address`, which is what every caller
/// holds and what every insertion site already has. Three consequences, and
/// the key form was chosen for the third: an `Address` orders by its tumbler
/// (M1's `Ord` delegates), so the map's iteration order — and with it the
/// determinism of [`docs_ever_containing`](M5State::docs_ever_containing) —
/// is the tumbler order; an `Address` serializes as its bare tumbler, so the
/// checkpoint encoding is a map of flat tumblers exactly as the data model
/// prescribes; and an `Address` re-validates on the way in (M1's `try_from`
/// shadow), so a key that is not T4-valid is a decode failure M2 reports as
/// corruption rather than a value some later read has to assert about.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct M5State {
    // Private but for `provenance`, which the reads R answers reach, and
    // `fork_sources` (below): only this module builds an `M5State` — a
    // default, a decoded checkpoint, or the fold's output — and every other
    // module reaches the arrangement map through `arrangement_of`
    // (ARCHITECTURE.md §The arrangement, "One fold").
    // Each map decodes entry by entry (`decode`), never through `im`'s own
    // visitor, which reserves room for the count a checkpoint body declares;
    // `provenance` and each document's run-lists decode the same way, behind
    // their own shadows.
    #[serde(deserialize_with = "entry_by_entry")]
    arrangements: im::OrdMap<Address, DocArrangement>,
    pub(crate) provenance: Provenance,
    #[serde(deserialize_with = "entry_by_entry")]
    birth_extents: im::OrdMap<Address, Nat>,
    #[serde(deserialize_with = "entry_by_entry")]
    shot_terms: im::OrdMap<Address, ShotTerms>,
    // Each `version`-minted document → the source it was born sharing
    // (SOURCE★). `pub(crate)` for the one read `reads.rs` holds; written by
    // the fold alone. No `#[serde(default)]`, by design: a checkpoint written
    // without this field must fail to decode and hand the open to the
    // journal, which recomputes the map — never decode as "no source" and
    // answer `None` for a fork.
    #[serde(deserialize_with = "entry_by_entry")]
    pub(crate) fork_sources: im::OrdMap<Address, Address>,
}

/// The shot's two client terms, per member the shot minted (signed-ops D25).
///
/// They are what a verifier of the member's entry signature needs beside the
/// member's own runs and address, and what nothing the arrangement holds
/// afterwards re-derives. Journaled in the shot's placing record
/// ([`M5Rec::ShotPlace`]), folded into [`M5State`]'s `shot_terms`, read by
/// [`M5State::shot_terms`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShotTerms {
    /// The positions the client placed: Σ width of the shot's runs.
    ///
    /// It is the count the shot's signed body leads with: positions
    /// `[1, placed]` of the member are the client's runs; at the mint what
    /// follows them is the base's carried tail, and a head member's later
    /// deposits land after it.
    pub placed: Nat,
    /// The base's extent the staged copy took; `None` in the birth shape.
    ///
    /// It is the shot's `base_extent`, in its signed body. The birth shape is
    /// the base absent (PUB-2.34): the absence is the birth bit, and there the
    /// count is `birth_extent(D.1)`, no tail being carried. The bit is the
    /// birth shape's, not every birth version's: a birth version minted off
    /// its memberless document as its base carries `Some` of the extent that
    /// copy took, and a `placed` short of its birth extent by the tail it
    /// carried.
    pub base_extent: Option<Nat>,
}

/// M5's sole journal delta, effect-level (Conflicts #4).
///
/// It carries concrete addresses/ordinals so the fold needs no upstream
/// access and never re-mints.
///
/// **Two seals**, governing two different things. Each variant is
/// `#[non_exhaustive]`, so no foreign crate can build an `M5Rec` by struct
/// literal — `stage_seat_link` and the op bodies (all in M5's crate) are the
/// only constructors a foreign crate can name. They are not the only ones it
/// can reach: `M5Rec` derives `Deserialize`, as M2's journal requires, so a
/// foreign crate can decode any record and stage it, bypassing every op's
/// checks. What such a record cannot bypass is what it carries or the fold
/// does — each `Run` it names re-enters `Run`'s own door, the `LinkSeat`
/// fold mints through that door, and the fold keeps the M/R coupling — and
/// it is outside the input class [`apply_m5`](M5State::apply_m5) names. The
/// type is `#[non_exhaustive]` too, because the variant set may grow (the
/// explicit-runs form of `VersionSnapshot`, Open decision #4, is one such
/// record): a foreign `match` must carry a `_` arm, and gains one variant
/// rather than a broken build when the set does grow. Neither seal touches
/// M5's own crate — [`M5State::apply_m5`] matches and destructures freely —
/// and the engine needs neither, `From`-lifting and folding the record whole.
///
/// The variant seal as a foreign crate meets it, a pair: the twin reaches a
/// record through the step that stages it and matches it; the refusal's one
/// difference is the struct literal. A bare `compile_fail` is satisfied by
/// any compile error, so the twin is what keeps the refusal a statement about
/// the seal. (The error code is checked on nightly only.)
///
/// ```
/// use skep_address::{validate, Nat, Tumbler};
/// use skep_arrangement::{stage_seat_link, M5Rec, M5State};
/// let address = |comps: &[u32]| {
///     validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).unwrap())
///         .unwrap()
/// };
/// let (doc, link) =
///     (address(&[1, 0, 1, 0, 1]), address(&[1, 0, 1, 0, 1, 0, 2, 1]));
/// let rec = stage_seat_link(&M5State::genesis(), &doc, &link).unwrap();
/// assert!(matches!(rec, M5Rec::LinkSeat { .. }));
/// ```
/// ```compile_fail,E0639
/// use skep_address::{validate, Nat, Tumbler};
/// use skep_arrangement::{stage_seat_link, M5Rec, M5State};
/// let address = |comps: &[u32]| {
///     validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).unwrap())
///         .unwrap()
/// };
/// let (doc, link) =
///     (address(&[1, 0, 1, 0, 1]), address(&[1, 0, 1, 0, 1, 0, 2, 1]));
/// let rec = M5Rec::LinkSeat { doc, link };
/// assert!(matches!(rec, M5Rec::LinkSeat { .. }));
/// ```
///
/// It grows at its end only: the journal writes a variant as its index and
/// its fields in order, with no framing (bincode), so a new variant is
/// appended after the last and no variant or field is ever inserted or
/// reordered — what keeps every record already journaled decoding as it was
/// written (ARCHITECTURE.md's rule for this slice's format).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum M5Rec {
    /// The placement INSERT, COPY and REINSTATE stage (J1★).
    ///
    /// It splices `runs` at content ordinal `at` and R-appends each placed
    /// run's iextent. It mints nothing, so it notes no birth extent, whatever
    /// document it names (BIRTH★). The shot's placement is
    /// [`ShotPlace`](M5Rec::ShotPlace), which carries terms this record has
    /// no place for.
    #[non_exhaustive]
    ContentPlace { doc: Address, at: Nat, runs: Vec<Run> },
    /// DELETE's removal: contract + reseat (no C, no R — ASN-0117 P0/P2).
    #[non_exhaustive]
    ContentRemove { doc: Address, from: Nat, width: Nat },
    /// REARRANGE's reorder: the cut sequence's 3|4 ordinals, tile-by-placement.
    ///
    /// It touches no C and no R. A cut is a V-position (ASN-0119); the record
    /// carries `ord(cⱼ)` for each, the subspace being fixed to s_C by the op's
    /// own validation.
    #[non_exhaustive]
    ContentReorder { doc: Address, cut_ordinals: Vec<Nat> },
    /// MAKELINK seating (no R — J-LV).
    #[non_exhaustive]
    LinkSeat { doc: Address, link: Address },
    /// CREATENEWVERSION's snapshot (share + R-append).
    ///
    /// `new` receives `source`'s content run-list, and `source` names the
    /// arrangement shared: for a record
    /// [`Vstream::version`](crate::Vstream::version) stages, the reading
    /// surface ([`reading_surface`](crate::reading_surface)) of the address it
    /// was asked about — that address itself unless it is a bare published
    /// document with members, whose trunk head it then names.
    ///
    /// **Linearization-at-fold**: the fold reads `source`'s then-current
    /// arrangement at this record's commit/replay slot — the record's effect
    /// is defined against the state at its commit position, not a pre-staged
    /// value. Exact under v1's single-applier M2 realization (nothing lands
    /// between a transact's base and its commit); any future M2 concurrency
    /// realization that lets disjoint-key commits land in that window must
    /// re-examine this record first (or move to the explicit-runs form, Open
    /// decision #4).
    ///
    /// **`source` is a fact the record must keep**, whatever form it takes
    /// (the fork-source design record, decision 9): the fold notes
    /// `new → source` in `fork_sources` (SOURCE★), and that map is the one
    /// place the fact survives the reclaim floor. The explicit-runs migration
    /// of Open decision #4 carries the runs beside `source`, never in place of
    /// it — a record that named the runs alone would leave every fork minted
    /// after it answering no source.
    #[non_exhaustive]
    VersionSnapshot { source: Address, new: Address },
    /// The publish shot's placing record (PUB-2.33; signed-ops D25).
    ///
    /// It carries the member's whole arrangement `runs` — the client's runs
    /// in order, the draft-native ones re-inserted, then the base's carried
    /// tail — spliced at content ordinal 1 + R-append (J1★), as `ContentPlace`
    /// at ordinal 1 would; and the shot's [`ShotTerms`] — the two client facts
    /// the arrangement cannot keep, `terms.placed` counting the client's
    /// positions alone and so short of `runs`' Σ width by the carried tail's —
    /// which the fold notes for the member. Pushed for every member the shot
    /// mints, an empty placement included: the terms exist whatever the
    /// placement holds, and a birth version born empty is noted at its birth,
    /// zero, by this record (BIRTH★).
    #[non_exhaustive]
    ShotPlace { doc: Address, runs: Vec<Run>, terms: ShotTerms },
}

impl M5State {
    /// Returns Σ₀ for M5, every field empty.
    ///
    /// That is `{}` arrangements, `{}` provenance, `{}` birth extents, `{}`
    /// shot terms, `{}` fork sources. Deterministic, per M2's
    /// byte-identical-genesis caller contract.
    pub fn genesis() -> M5State {
        M5State::default()
    }

    /// Returns `doc`'s arrangement, or the empty one when `doc` is absent.
    ///
    /// It is the absent-⇒-empty convention (the eager-lazy split with M3,
    /// stated on [`M5State`]) applied once, so no read decides for itself what
    /// an absent document answers and a new read inherits the convention
    /// rather than restating it. Every read of the map — the folds' included,
    /// which clone what they will update and read the content list a placement
    /// splices or a fork shares through [`content_list`](M5State::content_list)
    /// — comes through here, which leaves `arrangements` touched directly only
    /// by the writes that own it: the folds' `update`, and the three no-op
    /// branches that hand the map back whole. The field is private to this
    /// module, so outside it this is the compiler's rule and not a convention;
    /// a test that must see the map itself asks `arrangement_map`.
    pub(crate) fn arrangement_of(&self, doc: &Address) -> &DocArrangement {
        self.arrangements
            .get(doc)
            .unwrap_or_else(|| &*EMPTY_ARRANGEMENT)
    }

    /// Returns `doc`'s content run-list, empty for an absent document.
    pub(crate) fn content_list(&self, doc: &Address) -> &RunList {
        &self.arrangement_of(doc).content
    }

    /// Returns `doc`'s link run-list, empty for an absent document.
    pub(crate) fn link_list(&self, doc: &Address) -> &RunList {
        &self.arrangement_of(doc).link
    }

    /// Returns the arrangements map whole, for a test.
    ///
    /// A test asserts with it what a record left the map: every read applies
    /// the absent-⇒-empty convention, so none tells an absent entry from an
    /// empty one — the question `Provenance::is_recorded` answers for R.
    #[cfg(test)]
    pub(crate) fn arrangement_map(&self) -> &im::OrdMap<Address, DocArrangement> {
        &self.arrangements
    }

    /// Returns the map with `doc`'s content run-list replaced by `f` of it.
    ///
    /// An absent doc reads as the empty arrangement, asked of
    /// [`arrangement_of`](M5State::arrangement_of) as every read asks it.
    /// Stating the read-modify-write once leaves each editing fold arm showing
    /// only what distinguishes it: which run-list operation it performs, and
    /// what it does to R.
    #[must_use = "returns the updated arrangements map; it does not modify the receiver"]
    fn arrangements_with_content(
        &self,
        doc: &Address,
        f: impl FnOnce(&RunList) -> RunList,
    ) -> im::OrdMap<Address, DocArrangement> {
        let mut arr = self.arrangement_of(doc).clone();
        arr.content = f(&arr.content);
        self.arrangements.update(doc.clone(), arr)
    }

    /// Returns the map with `doc`'s link run-list replaced by `f` of it.
    ///
    /// It is the link-subspace twin of
    /// [`arrangements_with_content`](M5State::arrangements_with_content).
    #[must_use = "returns the updated arrangements map; it does not modify the receiver"]
    fn arrangements_with_link(
        &self,
        doc: &Address,
        f: impl FnOnce(&RunList) -> RunList,
    ) -> im::OrdMap<Address, DocArrangement> {
        let mut arr = self.arrangement_of(doc).clone();
        arr.link = f(&arr.link);
        self.arrangements.update(doc.clone(), arr)
    }

    /// Returns `birth_extents` with `doc`'s extent noted, where one is due.
    ///
    /// The extent is `born_with()`, asked only where it is wanted, and is due
    /// when `doc` is a birth version ([`is_birth_version`]) not yet noted;
    /// otherwise `birth_extents` come back as they stand. The two arms that
    /// mint a member call it — [`ShotPlace`](M5Rec::ShotPlace) and
    /// [`VersionSnapshot`](M5Rec::VersionSnapshot) — with the member their
    /// record mints and the count it leaves the member holding; a record that
    /// mints nothing never asks. BIRTH★ is this function's second test: an
    /// entry, once written, is what every later call hands back.
    #[must_use = "returns the updated birth extents; it does not modify the receiver"]
    fn birth_extents_noting(
        &self,
        doc: &Address,
        born_with: impl FnOnce() -> Nat,
    ) -> im::OrdMap<Address, Nat> {
        if !is_birth_version(doc) || self.birth_extents.contains_key(doc) {
            return self.birth_extents.clone();
        }
        self.birth_extents.update(doc.clone(), born_with())
    }

    /// Returns PUB-3.19's birth content, as a count: `member`'s minted extent.
    ///
    /// It is the content extent the birth version `member` — a trunk's `D.1`
    /// — was minted with (RES-276; R2-kickoff D2), the leading positions of
    /// its arrangement, which a deposit taken while it is the head never
    /// joins. `content_count(member)` is the live extent and follows every
    /// such deposit; this one is frozen at the mint, so positions
    /// `[1, birth_extent]` of the member are what an edition's claim was
    /// written over (PUB-3.10), and this extent answers the same as of every
    /// later `Seq`.
    ///
    /// Exact for a birth version born empty too: it answers a noted zero,
    /// frozen like any extent, however much the head has taken since —
    /// BIRTH★ on [`M5State`] states which records note an extent. No
    /// conforming mint is empty (PUB-3.11).
    ///
    /// `None` where no extent is noted — every address that is no birth
    /// version, and a birth version not yet minted — so a noted zero, a birth
    /// version born empty, and `None`, no birth at this address, are two
    /// answers. It answers the address named, as every read here does: a
    /// caller holding a document rather than its birth version asks the chain
    /// card's [`birth_version`](crate::birth_version) for that address first.
    /// One map lookup, reading no run; the extent is lent, as
    /// [`shot_terms`](M5State::shot_terms) lends the terms beside it, and a
    /// caller keeping it clones it.
    pub fn birth_extent(&self, member: &Address) -> Option<&Nat> {
        self.birth_extents.get(member)
    }

    /// Returns the shot terms of `member`: those of the shot that minted it.
    ///
    /// They are the two client terms ([`ShotTerms`]: `placed`,
    /// `base_extent`), which the doc-metadata read serves beside the birth
    /// version and a verifier of the member's entry signature composes its
    /// body from — or `None` for a member no shot's record names: a member an
    /// owned `version` minted, and every address that is no version member.
    /// Answers the address named — a trunk document answers `None`, never its
    /// head's — and reads no run. One map lookup.
    pub fn shot_terms(&self, member: &Address) -> Option<&ShotTerms> {
        self.shot_terms.get(member)
    }

    /// Folds `r` into a new state: the pure, deterministic M2 fold.
    ///
    /// It discharges M2's `apply` obligation (§3–§8 folds), dispatched by the
    /// engine's `World::apply` from the variant that carries `M5Rec` (the
    /// engine's `Record::Arrangement`) — on live commit and on replay alike.
    ///
    /// **Totality domain** (§10): total over minted-or-validly-recovered
    /// records — an `M5Rec` an op staged after validating its preconditions
    /// (every op validates before `stg.push`), or one M2 recovered with its
    /// journal/checkpoint integrity. An out-of-contract record (a
    /// `ContentPlace.at` past the append boundary, a `ContentRemove`
    /// overrunning the run-list, a cut vector violating R-PRE) arises only
    /// from corruption or from a record staged past the ops ([`M5Rec`]'s
    /// seals say how), is outside the input class, and is not re-validated
    /// here; the run-list clamps keep the fold panic-free regardless.
    /// Determinism for `VersionSnapshot` holds because records replay in
    /// journal order, so `source`'s arrangement is reconstructed to its
    /// fork-point value before the snapshot reads it.
    #[must_use = "apply_m5 returns the folded state; it does not modify the receiver"]
    pub fn apply_m5(&self, r: &M5Rec) -> M5State {
        match r {
            // §3/§5 fold: splice + eager coalesce, and append each placed
            // run's iextent to R in the same fold — one new M5State, one M2
            // root install, so a reader never observes M-updated-without-R
            // (J1★ ⇒ P4★/P4a; with INSERT's composite, J0 ⇒ P7a).
            //
            // No birth extent is noted here: a placement mints nothing, and a
            // birth version's extent is its mint's to note (BIRTH★). A
            // `ContentPlace` naming one is a deposit the head took, and one
            // that names it before its mint's record — which no op stages —
            // notes nothing rather than its own count as the birth.
            M5Rec::ContentPlace { doc, at, runs } => M5State {
                arrangements: self
                    .arrangements_with_content(doc, |c| c.splice_in(at, runs.iter().cloned())),
                provenance: self.provenance.append(doc, runs),
                birth_extents: self.birth_extents.clone(),
                shot_terms: self.shot_terms.clone(),
                fork_sources: self.fork_sources.clone(),
            },
            // The shot's placement (signed-ops D25): `ContentPlace` at
            // ordinal 1 — the same splice, the same R-append — and the
            // member's terms noted beside its birth extent. The birth extent
            // is noted here for a birth version (BIRTH★): the shot journals a
            // member's whole arrangement as one placement, in the commit that
            // mints it (PUB-3.11), so this record naming a birth version is
            // its mint and the count it leaves is the birth extent — zero for
            // a member born empty, since the record is pushed whatever the
            // placement holds. The count is read off the spliced list itself,
            // built once and then installed — the list this record leaves the
            // member holding, as the snapshot arm below counts the list it
            // shares. An empty placement leaves the arrangement absent under
            // the lazy convention (≡ empty), as the snapshot arm leaves an
            // empty source's `new`, and appends no provenance. No fork source
            // is noted: the shot mints its member off no source (SOURCE★).
            M5Rec::ShotPlace { doc, runs, terms } => {
                let content = self.content_list(doc).splice_in(&Nat::one(), runs.iter().cloned());
                let birth_extents = self.birth_extents_noting(doc, || content.total_width());
                let shot_terms = self.shot_terms.update(doc.clone(), terms.clone());
                if runs.is_empty() {
                    M5State {
                        arrangements: self.arrangements.clone(),
                        provenance: self.provenance.clone(),
                        birth_extents,
                        shot_terms,
                        fork_sources: self.fork_sources.clone(),
                    }
                } else {
                    M5State {
                        arrangements: self.arrangements_with_content(doc, |_| content),
                        provenance: self.provenance.append(doc, runs),
                        birth_extents,
                        shot_terms,
                        fork_sources: self.fork_sources.clone(),
                    }
                }
            }
            // §4 fold: split at `from` and `from + width`, drop the middle,
            // concat + eager coalesce. C and R untouched (NonDestruction is
            // structural — M5 has no content-reclamation path; P2 keeps every
            // R pair). A text delete never touches the link run-list (P4).
            M5Rec::ContentRemove { doc, from, width } => M5State {
                arrangements: self.arrangements_with_content(doc, |c| c.remove_range(from, width)),
                provenance: self.provenance.clone(),
                birth_extents: self.birth_extents.clone(),
                shot_terms: self.shot_terms.clone(),
                fork_sources: self.fork_sources.clone(),
            },
            // §6 fold: split at cut ordinals, tile by placement. Pure
            // permutation — C, L, R untouched (ASN-0119 RA1/RA6).
            M5Rec::ContentReorder { doc, cut_ordinals } => M5State {
                arrangements: self.arrangements_with_content(doc, |c| c.reorder(cut_ordinals)),
                provenance: self.provenance.clone(),
                birth_extents: self.birth_extents.clone(),
                shot_terms: self.shot_terms.clone(),
                fork_sources: self.fork_sources.clone(),
            },
            // §8 fold: append `link` after the link subspace's arranged
            // positions, coalescing with the prior link run if I-adjacent
            // (sequential A_L(d) allocations are — the maximally-merged link
            // list is a valid S8★ witness). No R append (J-LV).
            //
            // The seated address becomes a Run start, so it walks `Run`'s own
            // door rather than a struct literal: `stage_seat_link` establishes
            // the shape on the live path, but a record's `Address` re-enters
            // only M1's `validate` on the replay path, and T4-validity does
            // not imply a full element position. An address the door refuses
            // is a no-op here. The fold is infallible and runs inside
            // `Kernel::open`, so panicking is not the alternative; and placing
            // it is worse than dropping it, a link run whose I-extent covered a
            // whole document or a whole subspace refusing every later link of
            // that document for good, CL-UNIQ being I-extent membership.
            M5Rec::LinkSeat { doc, link } => M5State {
                arrangements: match Run::new(link.clone(), Nat::one()) {
                    Ok(seated) => self.arrangements_with_link(doc, |l| l.append(seated)),
                    Err(_) => self.arrangements.clone(),
                },
                provenance: self.provenance.clone(),
                birth_extents: self.birth_extents.clone(),
                shot_terms: self.shot_terms.clone(),
                fork_sources: self.fork_sources.clone(),
            },
            // §7 fold: share `source`'s then-current content run-list into
            // `new` (structural im share — O(1)) and append each shared run
            // as provenance (run, new). This copies the V→I map, not the
            // I-range (ASN-0123 V2): the share preserves multiplicity, so
            // within-document transclusion duplicates survive into the fork.
            // When the source content subspace is empty (n = 0) the fold
            // appends no provenance and skips the arrangements update,
            // leaving `new` absent under the lazy convention (≡ empty) —
            // V1's zero-content footprint with no redundant entry. Source is
            // untouched (V3); the fork diverges copy-on-write (V11).
            //
            // The two halves cost differently, and only one of them is
            // priced by the record. The arrangement share is O(1). The
            // R-append is Θ(#runs(source)) freshly-built spans — one per
            // run, each a pair of tumblers — and permanent (P2). This
            // record carries two addresses whatever the source holds, so
            // M2's `MAX_TXN_BYTES` weighs those two addresses and bounds
            // the expansion not at all; `ContentPlace`, which appends to R
            // by this same mechanism, carries its runs and is bounded by
            // that ceiling and, as COPY and REINSTATE stage it, by
            // `MAX_PLACED_RUNS` too. Replay re-pays it: the journal record
            // stays two addresses, so `k` fork records cost
            // `Σ #runs(sourceᵢ)` spans at every `Kernel::open` that replays
            // them, and a checkpoint carries the result. What would put this
            // append under the transaction budget where `ContentPlace`'s
            // already sits is the explicit-runs form of this record (Open
            // decision #4) — a second reason for that migration beside the
            // M2-concurrency one stated on the variant. `Vstream::version`
            // states who owns the bound meanwhile.
            //
            // The birth extent is noted on this arm too (BIRTH★): an owned
            // VERSION of a memberless published document mints its birth
            // version by this record, and the count shared is what that
            // version is born with. The record is staged whatever the surface
            // holds, so an empty birth is noted here as zero — one of the two
            // entries the empty branch writes, beside the fork source — and
            // every birth version holds its entry however it was born. A
            // cross-owner fork's `new` is a fresh document, no birth version,
            // and notes no birth extent.
            //
            // The fork source is noted on both branches (SOURCE★): `new` was
            // born sharing `source`, whatever `source` held — an empty
            // surface shares nothing and is a source all the same — and this
            // record is the one that says so. The entry is `new → source` as
            // the record carries it: the surface the op resolved, a member or
            // a bare document, and never a reading of it made here.
            M5Rec::VersionSnapshot { source, new } => {
                let content = self.content_list(source).clone();
                let birth_extents = self.birth_extents_noting(new, || content.total_width());
                let fork_sources = self.fork_sources.update(new.clone(), source.clone());
                if content.is_empty() {
                    M5State {
                        arrangements: self.arrangements.clone(),
                        provenance: self.provenance.clone(),
                        birth_extents,
                        shot_terms: self.shot_terms.clone(),
                        fork_sources,
                    }
                } else {
                    let provenance = self.provenance.append(new, content.iter());
                    let arr = DocArrangement {
                        content,
                        link: RunList::default(),
                    };
                    M5State {
                        arrangements: self.arrangements.update(new.clone(), arr),
                        provenance,
                        birth_extents,
                        shot_terms: self.shot_terms.clone(),
                        fork_sources,
                    }
                }
            }
        }
    }

    /// Returns `self`: the identity, M5 having no skip-serialized hints (§10).
    ///
    /// It is the default in v1; adding the inverse-arrangement or
    /// reverse-provenance hint (Open decisions #2/#3) obliges an override that
    /// reseeds exactly the fold-equivalent state.
    #[must_use = "rebuild_derived consumes the state and returns the seeded one"]
    pub fn rebuild_derived(self) -> M5State {
        self
    }
}

#[cfg(test)]
mod tests;
