//! §A / §3–§8 folds — M5's `WorldState` slice ([`M5State`]), its sole journal
//! delta ([`M5Rec`]), and the pure fold ([`M5State::apply_m5`]).

use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use skep_address::{content_subspace, link_subspace, Address, Nat};
use skep_namespace::first_version_address;

use crate::chain::trunk_of;
use crate::ops::run_origin_document;
use crate::provenance::Provenance;
use crate::run::Run;
use crate::runlist::RunList;
use crate::shot::PlacedSegment;

/// One document's POOM: the content and link run-lists (§Core data model).
/// Exactly these two subspaces exist, which is a fact about the arrangement
/// and so is answered by [`list`](DocArrangement::list) rather than restated
/// by each read that routes on a subspace numeral.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DocArrangement {
    pub(crate) content: RunList,
    pub(crate) link: RunList,
}

impl DocArrangement {
    /// The run-list `subspace` selects, or `None` when it names neither —
    /// `s_C` and `s_L` (M1's numerals) being the only two that exist. Every
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

/// Authoritative folded state: the per-document POOM, and the provenance
/// relation R (`Provenance`) co-located beside it (ASN-0075). The arrangement
/// is authoritative MUTABLE state recovered by replay — NOT a recomputable
/// hint (ASN-0047 P3); provenance is the append-only history housed next to
/// it, and it is a type of its own whose surface offers no removal, so the
/// permanence R promises holds by construction. `arrangements` is sparse: an
/// absent doc ⇒ empty arrangement (the eager-lazy split with M3). v1 has no
/// derived-hint fields ⇒ [`rebuild_derived`](M5State::rebuild_derived) is
/// the identity.
///
/// THE BIRTH EXTENTS (`birth_extents`; PUB-3.19 as RES-276 reads it, frozen
/// by the owner's ruling D2, 2026-09-17) are the third field, and the one
/// that is DERIVED: per BIRTH VERSION — a trunk's opening member `D.1` — the
/// content count that version was BORN with, which
/// [`birth_extent`](M5State::birth_extent) answers and the doc-metadata read
/// serves. They have no record of their own and no op writes them: the fold
/// notes each off the record that gives the version its arrangement — the
/// mint commit's own placement, or the snapshot an owned VERSION stages — so
/// replay re-derives them from the journal as it stands and the journal
/// carries nothing for them. They are NOT a recomputable hint all the same,
/// which is why the checkpoint carries them and `rebuild_derived` has nothing
/// to seed: while a birth version is the head a declared deposit appends to
/// its arrangement (PUB-2.66), the run-list merges an I-adjacent deposit INTO
/// the last birth run, and R keeps spans and no record boundary, so nothing
/// the arrangement holds afterwards says where the birth content ended.
/// Nothing reads them to decide a write.
///
/// THE SHOT TERMS (`shot_terms`; the signed-ops design record's D25, arm
/// (c′), owner-ruled 2026-09-29 — l6-A2) are the fourth field, and the one
/// that is JOURNALED per member: for every version member the SHOT minted,
/// the two CLIENT terms of that shot which nothing else the fold keeps
/// answers — the COUNT the client placed (Σ width of its runs, `placed`) and
/// the base's EXTENT the staged copy took (`base_extent`), an option whose
/// absence IS the birth bit (a first shot with `base` absent, where the count
/// is `birth_extent(D.1)`). They ride the shot's own placing record
/// ([`ShotPlace`](M5Rec::ShotPlace)), so they are hashed into the commit
/// chain, folded here, carried by every checkpoint, replayed on every replica
/// and read off the live snapshot by anyone holding the member's address
/// ([`shot_terms`](M5State::shot_terms)) — which is what a verifier of the
/// shot's entry signature needs beyond the member's own runs: the signature
/// binds the runs the client placed in the address form, `placed` says where
/// they end and the base's carried tail begins, `base_extent` is in the
/// signed bytes, and `base` itself is derived from the member's address. The
/// run-list erases the boundary between the client's last run and the
/// carried tail whenever the two are I-adjacent, so nothing the arrangement
/// holds afterwards could re-derive `placed`. Nothing reads them to decide a
/// write.
///
/// CLASS INVARIANTS, relating the fields. The reads state what they
/// answer; these are what makes those answers mean it.
///
/// * **R is append-only.** Structural: `Provenance` offers `append` and
///   reads, and no removal, so no fold arm can shorten any document's R↾doc
///   however the variant set grows (ASN-0047 P2).
/// * **P4★ — present containment is recorded.** For every `doc`, the current
///   content image `⋃ r.iextent()` over `content_runs(doc)` is contained in
///   `provenance.ever_contained(doc)`. Established by the two arms that
///   place: [`ContentPlace`](M5Rec::ContentPlace) appends exactly the
///   iextents it splices in, and [`VersionSnapshot`](M5Rec::VersionSnapshot)
///   appends exactly the iextents of the run-list it installs. Preserved by
///   the other three: [`ContentRemove`](M5Rec::ContentRemove) only contracts
///   the image, [`ContentReorder`](M5Rec::ContentReorder) permutes the same
///   arranged addresses, and [`LinkSeat`](M5Rec::LinkSeat) touches the link
///   run-list, which is no part of the content image. Splitting and
///   coalescing move the boundaries between runs and not the addresses they
///   cover, so the image is stable under both. On the DECODE path P4★ is
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
/// * **BIRTH★ — a birth version's extent is noted ONCE and never moved.**
///   `birth_extents` gains `m`'s entry at the first placing record that
///   names `m` — [`ShotPlace`](M5Rec::ShotPlace), which the shot journals
///   for every member it mints, an EMPTY placement included, or
///   [`VersionSnapshot`](M5Rec::VersionSnapshot), a snapshot of an EMPTY
///   source noting zero — and no later record touches it, so a deposit that
///   grows the head grows `content_count(m)` and not `birth_extent(m)`. On
///   the op path `birth_extent(m) ≤ content_count(m)`, and positions
///   `[1, birth_extent(m)]` of `m` are the arrangement it was minted with: a
///   published member admits no removal and no re-arrangement (PUB-2.11), and
///   a deposit lands past the arranged extent. The one state that escaped it
///   — a birth version the shot minted with no runs, whose first deposit was
///   read as its birth — closed when the shot's record began to carry its
///   terms and so to be journaled whatever the placement holds
///   (`ShotPlace`'s arm). On the DECODE path BIRTH★ is M2's integrity, as
///   P4★ is: a checkpoint carries `birth_extents` whole, and no door
///   re-establishes that each key is a birth version or each count its
///   mint's. A decoded state violating it faults nothing — no read does
///   arithmetic on an extent, and [`birth_extent`](M5State::birth_extent)
///   answers the count carried — but a consumer that takes the key set for
///   version members, as the engine's dump filter does, trusts the checkpoint
///   for it.
/// * **TERMS★ — a member's shot terms are the terms of the shot that minted
///   it.** `shot_terms` gains `m`'s entry at `m`'s own
///   [`ShotPlace`](M5Rec::ShotPlace), the record the commit that minted `m`
///   pushed, and no other record on the op path names `m` there: a member is
///   minted once, and the shot is the one op that mints a member with a
///   placement of its own. So `placed(m)` is a PREFIX of the arrangement `m`
///   was minted with — positions `[1, placed(m)]` are the client's runs and
///   `(placed(m), birth_extent(m)]` (or the count at the mint, for a later
///   member) the base's carried tail — and
///   [`address_form_of`](M5State::address_form_of) reads that prefix back.
///   On the DECODE path, as BIRTH★: carried whole, re-established by no
///   door.
///
/// Two public reads mean what they say only under P4★:
/// [`deletions`](M5State::deletions) is the deleted set rather than an
/// arbitrary difference, and [`docs_ever_containing`](M5State::docs_ever_containing)
/// is a superset with no false negatives — the property that makes narrowing
/// it by [`arranges_any`](M5State::arranges_any) sound.
///
/// Three things a caller may rely on under D-SEQ★, each restated where it is
/// answered so a reader need not come here for it:
///
/// * [`point`](M5State::point) answers `Some` at `[s, k]` exactly for
///   `1 ≤ k ≤ n_s` — the arranged positions are an interval, so one bound
///   settles membership;
/// * [`content_count`](M5State::content_count) is both the width sum of
///   [`content_runs`](M5State::content_runs) and the LARGEST arranged content
///   ordinal, and [`link_count`](M5State::link_count)/[`link_runs`](M5State::link_runs)
///   likewise — a count, not a total that some hole might over-report;
/// * the runs [`resolve`](M5State::resolve) hands back tile V CONTIGUOUSLY,
///   so a caller that needs their V-starts accumulates widths instead of
///   locating each run again.
///
/// EVERY READ HERE ANSWERS THE ADDRESS NAMED. `resolve`, `iter_resolve`,
/// `point`, `image`, `content_runs`, `link_runs`, `content_count`,
/// `link_count`, `content_run_count`, `link_run_count`, `project`,
/// `arranges_any`, `deletions` and `recorded_span_count` never float: asked
/// of a bare published document with members, they answer its own pre-chain
/// arrangement, which the chain has superseded, and its own R↾doc, not the
/// trunk head's. Head-float (PUB-2.49) is a composition the READER makes —
/// [`reading_surface`](crate::reading_surface) first, then the read — as
/// M6's and M8's arrangement readers do. [`birth_extent`](M5State::birth_extent)
/// answers the address named as well: asked of a bare document it answers
/// zero — the document is no birth version — and never its `D.1`'s extent.
///
/// Every field keys by the document `Address`, which is what every caller
/// holds and what every insertion site already had. Three consequences, and
/// the key form was chosen for the third: an `Address` orders by its tumbler
/// (M1's `Ord` delegates), so the map's iteration order — and with it the
/// determinism of [`docs_ever_containing`](M5State::docs_ever_containing) —
/// is the tumbler order; an `Address` serializes AS its bare tumbler, so the
/// checkpoint encoding is a map of flat tumblers exactly as the data model
/// prescribes; and an `Address` re-validates on the way in (M1's `try_from`
/// shadow), so a key that is not T4-valid is a decode failure M2 reports as
/// corruption rather than a value some later read has to assert about.
///
/// Serialization needs the `im` crate's `serde` feature and
/// `Tumbler: Serialize/DeserializeOwned` (M1's `num-bigint` serde feature) —
/// both carried by this crate's dependencies (Build precondition).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct M5State {
    pub(crate) arrangements: im::OrdMap<Address, DocArrangement>,
    pub(crate) provenance: Provenance,
    pub(crate) birth_extents: im::OrdMap<Address, Nat>,
    pub(crate) shot_terms: im::OrdMap<Address, ShotTerms>,
}

/// THE SHOT'S TWO CLIENT TERMS, per member the shot minted (the signed-ops
/// design record's D25, arm (c′)): what a verifier of the member's entry
/// signature needs beside the member's own runs and address, and what
/// nothing the arrangement holds afterwards re-derives. Journaled in the
/// shot's placing record ([`M5Rec::ShotPlace`]), folded into
/// [`M5State`]'s `shot_terms`, read by [`M5State::shot_terms`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShotTerms {
    /// The positions the client PLACED — Σ width of the shot's runs, the
    /// count its signed body leads with: positions `[1, placed]` of the
    /// member are the client's runs, and what follows is the base's carried
    /// tail.
    pub placed: Nat,
    /// The extent of the base the staged copy TOOK — the shot's
    /// `base_extent`, in its signed body — or `None` in the BIRTH SHAPE, the
    /// base absent (PUB-2.34): the absence IS the birth bit, and there the
    /// count is `birth_extent(D.1)`, no tail being carried.
    pub base_extent: Option<Nat>,
}

/// Is `doc` a BIRTH VERSION — the opening member `D.1` of its trunk's version
/// chain, the one member whose extent `birth_extents` holds? Asked of the two
/// owners of that fact rather than respelled: [`trunk_of`] for the trunk
/// (PUB-2.15) and M3's [`first_version_address`] for where its chain opens.
/// Pure address arithmetic — the fold reads no slice but its own — and
/// settled at the first comparison for every address that is no version
/// member, which is every draft a placement names. A DAUGHTER's first member
/// (`D.3.1`) is not one: its trunk's chain opens at `D.1`.
fn is_birth_version(doc: &Address) -> bool {
    let trunk = trunk_of(doc);
    trunk != *doc && first_version_address(&trunk).as_ref() == Some(doc)
}

/// M5's sole journal delta — effect-level (carries concrete
/// addresses/ordinals so the fold needs no upstream access and never
/// re-mints; Conflicts #4).
///
/// TWO SEALS, governing two different things. Each VARIANT is
/// `#[non_exhaustive]`, so no foreign crate can build an `M5Rec` by struct
/// literal — `stage_seat_link` and the op bodies (all in M5's crate) are the
/// only constructors a foreign crate can NAME. They are not the only ones it
/// can REACH: `M5Rec` derives `Deserialize`, as M2's journal requires, so a
/// foreign crate can decode any record and stage it, bypassing every op's
/// checks. What such a record cannot bypass is what it carries or the fold
/// does — each `Run` it names re-enters `Run`'s own door, the `LinkSeat`
/// fold mints through that door, and the fold keeps the M/R coupling — and
/// it is outside the input class [`apply_m5`](M5State::apply_m5) names. The
/// TYPE is `#[non_exhaustive]` too, because the variant set may grow (the
/// explicit-runs form of `VersionSnapshot`, Open decision #4, is one such
/// record): a foreign `match` must carry a `_` arm, and gains one variant
/// rather than a broken build when the set does grow. Neither seal touches
/// M5's own crate — [`M5State::apply_m5`] matches and destructures freely —
/// and the engine needs neither, `From`-lifting and folding the record whole.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum M5Rec {
    /// INSERT and COPY: splice `runs` at content ordinal `at` + R-append each
    /// placed run's iextent (J1★). The publish shot's placement was this
    /// record until D25's (c′) gave it terms of its own
    /// ([`ShotPlace`](M5Rec::ShotPlace)); this variant's bytes did not move
    /// for that — the new one was appended to the set, so an `insert`'s or a
    /// `copy`'s record encodes as it always did.
    #[non_exhaustive]
    ContentPlace { doc: Address, at: Nat, runs: Vec<Run> },
    /// DELETE: contract + reseat (no C, no R — ASN-0117 P0/P2).
    #[non_exhaustive]
    ContentRemove { doc: Address, from: Nat, width: Nat },
    /// REARRANGE: the 3|4 ORDINALS of the cut sequence, tile-by-placement (no
    /// C, no R). A cut is a V-position (ASN-0119); the record carries
    /// `ord(cⱼ)` for each, the subspace being fixed to s_C by the op's own
    /// validation.
    #[non_exhaustive]
    ContentReorder { doc: Address, cut_ordinals: Vec<Nat> },
    /// MAKELINK seating (no R — J-LV).
    #[non_exhaustive]
    LinkSeat { doc: Address, link: Address },
    /// CREATENEWVERSION (share + R-append). `new` receives `source`'s content
    /// run-list, and `source` names the arrangement shared: for a record
    /// [`Vstream::version`](crate::Vstream::version) stages, the READING
    /// SURFACE ([`reading_surface`](crate::reading_surface)) of the address it
    /// was asked about — that address itself unless it is a bare published
    /// document with members, whose trunk head it then names.
    /// LINEARIZATION-AT-FOLD: the fold
    /// reads `source`'s then-current arrangement at THIS record's
    /// commit/replay slot — the record's effect is defined against the state
    /// at its commit position, not a pre-staged value. Exact under v1's
    /// single-applier M2 realization (nothing lands between a transact's base
    /// and its commit); any future M2 concurrency realization that lets
    /// disjoint-key commits land in that window MUST re-examine this record
    /// first (or move to the explicit-runs form, Open decision #4).
    #[non_exhaustive]
    VersionSnapshot { source: Address, new: Address },
    /// THE PUBLISH SHOT's placing record (PUB-2.33; the signed-ops design
    /// record's D25, arm (c′), owner-ruled 2026-09-29): the member's WHOLE
    /// arrangement `runs` — the client's runs in order, the draft-native ones
    /// re-inserted, then the base's carried tail — spliced at content
    /// ordinal 1 + R-append (J1★), as `ContentPlace` at ordinal 1 would; AND
    /// the shot's two CLIENT terms, `placed` — Σ width of the client's runs,
    /// the count its signed body leads with — and `base_extent`, the base's
    /// extent the staged copy took, `None` in the birth shape. Pushed for
    /// EVERY member the shot mints, an empty placement included: the terms
    /// exist whatever the placement holds, and a member born empty is noted
    /// at its true birth (zero) rather than read off its first deposit — the
    /// residue BIRTH★ carried until this record.
    ///
    /// The LAST variant, appended (2026-09-29) so the five before it keep
    /// their indices — bincode encodes a variant as its index — and every
    /// `insert`, `copy`, `delete`, `rearrange`, `make_link` and `version`
    /// record on disk decodes as before. What moved is only what the fixture
    /// under `tests/golden/` (skep-kernel) pins: regenerated once under the
    /// unchanged stamps, by the owner's no-stamp ruling (dev boards
    /// regenerate).
    #[non_exhaustive]
    ShotPlace { doc: Address, runs: Vec<Run>, placed: Nat, base_extent: Option<Nat> },
}

impl M5State {
    /// Σ₀ for M5: `{}` arrangements, `{}` provenance, `{}` birth extents,
    /// `{}` shot terms. Deterministic, per M2's byte-identical-genesis caller
    /// contract.
    pub fn genesis() -> M5State {
        M5State::default()
    }

    /// The arrangements map with `doc`'s content run-list replaced by `f` of
    /// the current one — an absent doc reading as the empty arrangement,
    /// asked of [`arrangement_of`](M5State::arrangement_of) as every read
    /// asks it. Stating the read-modify-write once leaves each editing fold
    /// arm showing only what distinguishes it: which run-list operation it
    /// performs, and what it does to R.
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

    /// The link-subspace twin of
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

    /// `birth_extents` with `doc`'s extent NOTED — `born_with()`, asked only
    /// where it is wanted — when `doc` is a birth version
    /// ([`is_birth_version`]) not yet noted; `birth_extents` as they stand
    /// otherwise. The two placing arms call it with the document their record
    /// places into and the count the record leaves it holding, and BIRTH★ is
    /// this function's second test: an entry, once written, is what every
    /// later call hands back.
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

    /// PUB-3.19's BIRTH CONTENT, as a count (RES-276; the owner's D2): the
    /// content extent the birth version `member` — a trunk's `D.1` — was
    /// MINTED with, the leading runs of its arrangement, which a deposit
    /// taken while it is the head never joins — one state excepted, below.
    /// `content_count(member)` is the live extent and follows every such
    /// deposit; this one is frozen at the mint, so positions
    /// `[1, birth_extent]` of the member are what an edition's claim was
    /// written over (PUB-3.10), and this extent answers the same as of every
    /// later `Seq`.
    ///
    /// EXACT for a birth version born EMPTY too: the shot journals its
    /// placing record for every member it mints, an empty placement included
    /// ([`M5Rec::ShotPlace`] carries the shot's terms whatever the placement
    /// holds), so an empty birth is noted at zero by its own mint — as a
    /// birth version an owned VERSION mints empty is by its own snapshot —
    /// and its first deposit grows `content_count` alone. (Until the record
    /// carried the terms, an empty shot pushed no placement and that first
    /// deposit was read as the birth — BIRTH★'s one residue, closed.) No
    /// conforming mint is empty (PUB-3.11).
    ///
    /// Zero for an address with no extent noted: every address that is no
    /// birth version — it answers the address named, as every read here does,
    /// and a caller asks M3 first whether the member exists at all. One map
    /// lookup, reading no run.
    pub fn birth_extent(&self, member: &Address) -> Nat {
        self.birth_extents.get(member).cloned().unwrap_or_default()
    }

    /// THE SHOT TERMS of `member` — the two client terms of the shot that
    /// minted it ([`ShotTerms`]: `placed`, `base_extent`), which the
    /// doc-metadata read serves beside the birth version and a verifier of
    /// the member's entry signature composes its body from — or `None` for a
    /// member no shot's record names: a birth version an owned `version`
    /// minted, a member minted before the record carried the terms, and every
    /// address that is no version member. Answers the address named — a
    /// trunk document answers `None`, never its head's — and reads no run.
    /// One map lookup.
    pub fn shot_terms(&self, member: &Address) -> Option<&ShotTerms> {
        self.shot_terms.get(member)
    }

    /// THE ADDRESS FORM READ AT THE MEMBER (l6-A4 = r6-4, owner-ruled
    /// 2026-09-29): `member`'s first `placed` content positions — the runs
    /// the client placed, which its entry signature covers, ahead of the
    /// base's carried tail — as [`PlacedSegment`]s in V-order, each run
    /// classed by its ORIGIN DOCUMENT as the commit left it: a run of the
    /// member's own trunk is [`Copied`](PlacedSegment::Copied) — the shot
    /// document's own I-space placed by reference, and the staging draft's
    /// text the commit re-inserted under that trunk, told apart by nothing
    /// here and signed alike, BY VALUE — and a run of any other document is a
    /// [`Window`](PlacedSegment::Window), signed BY ADDRESS. The runs are the
    /// arrangement's own, maximally merged, the last one CLIPPED where the
    /// client's positions end; so what this answers for a committed member is
    /// what [`Shot::address_form`](crate::Shot::address_form) answered for the
    /// request that minted it, and a verifier holding the member composes the
    /// shot's signed body with no request in hand. `placed` is the caller's —
    /// the member's own [`shot_terms`](M5State::shot_terms), or a count a
    /// checker chooses. A member with fewer positions than `placed` answers
    /// what it has; an absent arrangement answers nothing.
    pub fn address_form_of(&self, member: &Address, placed: &Nat) -> Vec<PlacedSegment> {
        let trunk = trunk_of(member);
        let mut left = placed.clone();
        let mut out = Vec::new();
        for run in self.content_runs(member) {
            if left.is_zero() {
                break;
            }
            // A propagating site: the start is a resident run's own, and a
            // width clipped to the positions left is at least one.
            let taken = if *run.width() > left {
                Run { i_start: run.i_start.clone(), width: left.clone() }
            } else {
                run.clone()
            };
            left = &left - taken.width();
            let copied = run_origin_document(&taken).as_ref() == Some(&trunk);
            out.push(if copied { PlacedSegment::Copied(taken) } else { PlacedSegment::Window(taken) });
        }
        out
    }

    /// The pure/deterministic M2 fold (§3–§8 folds; M2's `apply` obligation),
    /// dispatched by the engine's `World::apply` from the variant that
    /// carries `M5Rec` (the engine's `Record::Arrangement`) — on live commit
    /// and on replay alike.
    ///
    /// TOTALITY DOMAIN (§10): total over minted-or-validly-recovered records
    /// — an `M5Rec` an op staged after validating its preconditions (every
    /// op validates before `stg.push`), or one M2 recovered with its
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
            // run's iextent to R IN THE SAME fold — one new M5State, one M2
            // root install, so a reader never observes M-updated-without-R
            // (J1★ ⇒ P4★/P4a; with INSERT's composite, J0 ⇒ P7a).
            //
            // THE BIRTH EXTENT is noted on this arm too (BIRTH★; PUB-3.19,
            // RES-276), though on the op path no placement here is a mint's:
            // the shot's placement is `ShotPlace`'s below, and an INSERT or
            // COPY naming a birth version is a deposit the head took, which
            // finds its extent already noted by the mint's own record. The
            // arm keeps the note all the same, as the fold's totality asks —
            // a record outside the op path's order is folded, not judged.
            M5Rec::ContentPlace { doc, at, runs } => {
                let content = self.content_list(doc).splice_in(at, runs.iter().cloned());
                let birth_extents = self.birth_extents_noting(doc, || content.total_width());
                M5State {
                    arrangements: self.arrangements_with_content(doc, |_| content),
                    provenance: self.provenance.append(doc, runs),
                    birth_extents,
                    shot_terms: self.shot_terms.clone(),
                }
            }
            // THE SHOT's placement (D25 (c′)): `ContentPlace` at ordinal 1 —
            // the same splice, the same R-append — and the member's TERMS
            // noted beside its birth extent. THE BIRTH EXTENT is noted here
            // for a birth version (BIRTH★): the shot journals a member's WHOLE
            // arrangement as one placement, in the commit that mints it
            // (PUB-3.11), so this record naming a birth version IS its mint
            // and the count it leaves is the birth extent — zero for a member
            // born EMPTY, since the record is pushed whatever the placement
            // holds. The count is read off the spliced list itself, built
            // once and then installed — the list this record leaves the
            // member holding, as the snapshot arm below counts the list it
            // shares. An empty placement leaves the arrangement ABSENT under
            // the lazy convention (≡ empty), as the snapshot arm leaves an
            // empty source's `new`, and appends no provenance.
            M5Rec::ShotPlace { doc, runs, placed, base_extent } => {
                let content = self.content_list(doc).splice_in(&Nat::one(), runs.iter().cloned());
                let birth_extents = self.birth_extents_noting(doc, || content.total_width());
                let shot_terms = self.shot_terms.update(
                    doc.clone(),
                    ShotTerms { placed: placed.clone(), base_extent: base_extent.clone() },
                );
                if runs.is_empty() {
                    M5State {
                        arrangements: self.arrangements.clone(),
                        provenance: self.provenance.clone(),
                        birth_extents,
                        shot_terms,
                    }
                } else {
                    M5State {
                        arrangements: self.arrangements_with_content(doc, |_| content),
                        provenance: self.provenance.append(doc, runs),
                        birth_extents,
                        shot_terms,
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
            },
            // §6 fold: split at cut ordinals, tile by placement. Pure
            // permutation — C, L, R untouched (ASN-0119 RA1/RA6).
            M5Rec::ContentReorder { doc, cut_ordinals } => M5State {
                arrangements: self.arrangements_with_content(doc, |c| c.reorder(cut_ordinals)),
                provenance: self.provenance.clone(),
                birth_extents: self.birth_extents.clone(),
                shot_terms: self.shot_terms.clone(),
            },
            // §8 fold: append `link` after the link subspace's arranged
            // positions, coalescing with the prior link run if I-adjacent
            // (sequential A_L(d) allocations are — the maximally-merged link
            // list is a valid S8★ witness). NO R append (J-LV).
            //
            // The seated address becomes a Run START, so it walks `Run`'s own
            // door rather than a struct literal: `stage_seat_link` establishes
            // the shape on the live path, but a record's `Address` re-enters
            // only M1's `validate` on the REPLAY path, and T4-validity does
            // not imply a full element position. An address the door refuses
            // is a NO-OP here. The fold is infallible and runs inside
            // `Kernel::open`, so panicking is not the alternative; and placing
            // it is worse than dropping it, a link run whose I-extent covered a
            // whole document or a whole subspace refusing every later link of
            // that document for good, CL-UNIQ being I-extent membership.
            M5Rec::LinkSeat { doc, link } => M5State {
                arrangements: match Run::new(link.clone(), Nat::from(1u32)) {
                    Ok(seated) => self.arrangements_with_link(doc, |l| l.append(seated)),
                    Err(_) => self.arrangements.clone(),
                },
                provenance: self.provenance.clone(),
                birth_extents: self.birth_extents.clone(),
                shot_terms: self.shot_terms.clone(),
            },
            // §7 fold: share `source`'s then-current content run-list into
            // `new` (structural im share — O(1)) and append each shared run
            // as provenance (run, new). This copies the V→I MAP, not the
            // I-range (ASN-0123 V2): the share preserves multiplicity, so
            // within-document transclusion duplicates survive into the fork.
            // When the source content subspace is empty (n = 0) the fold
            // appends no provenance and skips the arrangements update,
            // leaving `new` ABSENT under the lazy convention (≡ empty) —
            // V1's zero-content footprint with no redundant entry. Source is
            // untouched (V3); the fork diverges copy-on-write (V11).
            //
            // THE TWO HALVES COST DIFFERENTLY, and only one of them is
            // priced by the record. The arrangement share is O(1). The
            // R-append is Θ(#runs(source)) freshly-built spans — one per
            // run, each a pair of tumblers — and permanent (P2). This
            // record carries two addresses whatever the source holds, so
            // M2's `MAX_TXN_BYTES` weighs those two addresses and bounds
            // the expansion not at all; `ContentPlace`, which appends to R
            // by this same mechanism, carries its runs and is bounded twice
            // over (by that ceiling and by `MAX_PLACED_RUNS`). REPLAY
            // RE-PAYS IT: the journal record stays two addresses, so `k`
            // fork records cost `Σ #runs(sourceᵢ)` spans at every
            // `Kernel::open`, and a checkpoint carries the result. What
            // would put this append under the transaction budget where
            // `ContentPlace`'s already sits is the explicit-runs form of
            // this record (Open decision #4) — a second reason for that
            // migration beside the M2-concurrency one stated on the variant.
            // `Vstream::version` states who owns the bound meanwhile.
            //
            // THE BIRTH EXTENT is noted on this arm too (BIRTH★): an owned
            // VERSION of a memberless published document mints its birth
            // version by this record, and the count shared is what that
            // version is born with. The record is staged whatever the surface
            // holds, so an EMPTY birth is noted here as ZERO — the one entry
            // the empty arm writes, and what keeps the version's first deposit
            // from reading as its birth. A cross-owner fork's `new` is a fresh
            // document, no birth version, and notes nothing.
            M5Rec::VersionSnapshot { source, new } => {
                let content = self.content_list(source).clone();
                let birth_extents = self.birth_extents_noting(new, || content.total_width());
                if content.is_empty() {
                    M5State {
                        arrangements: self.arrangements.clone(),
                        provenance: self.provenance.clone(),
                        birth_extents,
                        shot_terms: self.shot_terms.clone(),
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
                    }
                }
            }
        }
    }

    /// Default identity in v1 — M5 has no skip-serialized hints (§10); adding
    /// the inverse-arrangement or reverse-provenance hint (Open decisions
    /// #2/#3) obliges an override that reseeds exactly the fold-equivalent
    /// state.
    #[must_use = "rebuild_derived consumes the state and returns the seeded one"]
    pub fn rebuild_derived(self) -> M5State {
        self
    }
}

#[cfg(test)]
mod tests;
