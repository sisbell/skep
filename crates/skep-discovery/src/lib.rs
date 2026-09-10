//! # skep-discovery — M8: Link Query & Discovery
//!
//! The **read-only query/presentation layer over the link subsystem**: given
//! a content region it answers *which links touch here*; given a four-set
//! descriptor it answers *which links match*; and it counts, paginates,
//! projects, retrieves endsets, previews delete-orphaning, and traces
//! supersession lineage — all by composing M7's spanfilade and behavior atoms
//! (`stab`/`match_links`/`type_slice`), M5's arrangement, and M3's registry
//! over ONE M2 snapshot per operation. One thing well: **turn upstream
//! link/arrangement/registry state into the answers readers ask, owning no
//! authoritative state and no index** — every answer is recomputed from
//! upstream on each call, so present-tense correctness (ASN-0108 W7) is free
//! and "recovery" is trivial (M8 persists nothing).
//!
//! Two query families, deliberately distinct (ASN-0121 is explicit that
//! neither restricts the other; Conflicts #2): the **region family**
//! (V-anchored, present-tense, doc-gated, disjunctive over slots — ASN-0127/
//! 0131) and the **descriptor family** (address-keyed, conjunctive,
//! link-store-local, monotone absent retraction — ASN-0121/0132). Both are
//! **addressable-filtered**: every present-state primitive is queried with
//! `View::Active`, so a result is the selection index ASN-0131 writes
//! `sel = findlinks ∩ addressable` and a nullified link never surfaces
//! (Conflicts #8 — a deliberate divergence from ASN-0127/0108's
//! foundations, which no addressability filter narrows). `delete_orphans`
//! and [`addressably_discoverable_from_on`] narrow the same way, the latter
//! diverging from ASN-0117/0098 by conjoining `is_active` onto LP12
//! discoverability.
//!
//! Two reads depart from that, and a caller building a live-links view needs
//! both:
//!
//! * [`project_on`] is NOT ADDRESSABLE-FILTERED — coverage reaches it
//!   through M7's `followlink`, which takes no `View` and reports what is
//!   recorded, so a retracted link still projects the V-positions it covers.
//!   That is ASN-0098's `project` unchanged; the addressable-filtered
//!   question it looks like it answers is
//!   [`addressably_discoverable_from_on`]'s.
//! * the lineage family ([`in_claims_on`]/[`out_claims_on`]) takes a `View`,
//!   so the caller chooses: `Active` yields the operative graph, `Audit` the
//!   full history including nullified claims, each disclosing its own
//!   activity in [`SupClaim::active`]. Under EVERY view a claim's `old`/`new`
//!   are the addresses it NAMES, read out as recorded — the view filters
//!   claims, never their endpoints, so a live claim can name a nullified
//!   link.
//!
//! Windowing (ASN-0108) is a stateless key-cut over M7's native
//! `OrdSet<Address>` — address order IS the permanent enumeration key
//! (Conflicts #3), so the cursor survives orphaning and M8 pages with no
//! index of its own.
//!
//! Every arrangement read here but one is of `d`'s READING SURFACE — M5's
//! `reading_surface`, the one pin of HEAD-FLOAT (PUB-2.49, PUB-2.50,
//! PUB-2.53), which states what each kind of address answers from. The
//! region family floats through [`image_on`], and the pointwise pair each
//! through its own read of the runs, so the two agree about which links
//! reach `d`. The one that does not float is
//! [`delete_orphans_on`]: it previews DELETE, which edits `d`'s own
//! arrangement and refuses every published target, so on every `d` DELETE
//! admits, `d` IS its reading surface. On a published `d` the two part and
//! the preview still answers — a gap, stated on the preview, and not a
//! decision.
//!
//! M8 does almost no span algebra — and never the level-gated kind:
//! coverage-overlap matching goes through M7, I→V through M5, query endsets
//! through `Run::iextent` + `Endset::from_spans`; the lone pointwise span
//! comparison is `addressably_discoverable_from`'s level-gate-free
//! `classify_spans` touch test (§5).
//!
//! ## The home rule
//!
//! A second narrowing, by READER where the first is by view: THE HOME RULE
//! (PUB round 2, lane 3.3; PUB-6.13) — a link is shown only if the reader
//! may read its HOME. M8 takes the reader as the caller's DOCUMENT
//! predicate, `readable`, and never sees a principal, a grant or the read
//! predicate's clauses. It composes that predicate with the home projection
//! in ONE crate-internal element, because asked of a link instead of its
//! home the predicate answers true and the rule admits every link.
//!
//! It is orthogonal to `View::Active`, and to the descriptor's own `home`
//! slot, which is a COVERAGE constraint (CN-STAB) and not an authorization.
//! It is applied at link IDENTITY, in the two shapes PUB names, by the
//! twelve reads that take the predicate as their last argument:
//!
//! * the RESULT-SET FILTER (PUB-6.13), on the ten RESULT-SET reads —
//!   `findlinks`, `count` and `window` in both families,
//!   [`retrieve_endsets_on`], [`delete_orphans_on`] and the lineage pair —
//!   which drop every result link the rule refuses, and count and page the
//!   survivors;
//! * the ABSENCE RULE (PUB-6.6), on the POINTWISE pair's `a` ARGUMENT, since
//!   neither answer names a link: an `a` the rule refuses is ABSENT, which
//!   [`project_on`] answers `Err(NotALink)` and
//!   [`addressably_discoverable_from_on`] `Ok(false)` — after the document
//!   gate, and ahead of the resident-link read so a refused link and an
//!   address naming nothing answer alike.
//!
//! Neither is the PER-RUN MASK (PUB-6.41, M6's `retrieve_v_masked`), which
//! withholds in place; nothing here applies it. [`image_on`] alone takes no
//! predicate: its answer names I-runs and no link. The division of labour is
//! the same everywhere: a NAMED document's own readability is the caller's
//! consult, before dispatch, and the homes of the links M8 names or is asked
//! about are M8's.
//!
//! A HARNESS caller — one answering for no reader class, as the engine's
//! cross-store lifecycle test and this crate's suite do — passes the TOTAL
//! predicate, admitting every home, visibly at its call site, and
//! [`LinkQuery`], which names no reader class, does so in all twelve. Naming
//! no reader class is not reading as the guest: a request that carries no
//! principal reads at the GUEST class (PUB-1.31 with no principal —
//! published documents alone) and passes that class's predicate, as M10 does
//! for every unbound session. The total predicate is never a request's.
//!
//! ## Budgets
//!
//! Two, both in the region file that owns the shape they price, and both
//! REFUSALS rather than truncations — a short answer silently drops links,
//! and no caller can tell one from a true answer.
//! [`MAX_IMAGE_RUNS`] is one constant held at the four reads of a document's
//! runs, each over the run count its own work multiplies; the constant states
//! the four counts and how their refusals relate. Its SQUARE holds the two
//! joins a run count alone does not price — the run-list walk [`image_on`]
//! asks of M5, and the touch test of a link's whole coverage behind the
//! pointwise pair. [`MAX_ENDSET_SPANS`] bounds what a RETRIEVEENDSETS answer
//! carries, the one quantity here the store supplies rather than the request.
//!
//! [`delete_orphans_on`] refuses under a word of its own,
//! [`OrphanError::ImageTooLarge`]: its other verdicts are drawn from M5's
//! `DeleteError`, and DELETE, which stabs nothing, has no word for a budget.
//!
//! What no number here reaches: `|links|`, `#runs(d)` and any one link's
//! endset size are the WORLD's, so they stay with request rate and
//! concurrency — M10's, as the request lifecycle's owner. These bound what a
//! request multiplies those quantities by, never the quantities.
//!
//! ## Cost
//!
//! What each read asks of M7's link store, counted in M7's primitives (M7
//! states `stab` and `match_links` as scans of the store in v1). A caller
//! that admission-controls these reads — the daemon's scan pool does —
//! prices them from this list, and a change to any line is a change to this
//! interface.
//!
//! * [`image_on`] — no link-store read; one M5 `resolve` per region span,
//!   each a walk of the reading surface's run-list from its first run, the
//!   region's whole walk held to `MAX_IMAGE_RUNS²` — and, for a region whose
//!   reach in positions alone passes that, one read of the surface's content
//!   runs to count them.
//! * the region family ([`findlinks_v_on`], [`count_v_on`], [`window_v_on`],
//!   [`retrieve_endsets_on`]) — three `stab`s, one per v1 slot, over the
//!   image's runs; none when the image is empty. [`retrieve_endsets_on`]
//!   adds one `readlink` per candidate the home rule admits.
//! * the descriptor family ([`findlinks_ftt_on`], [`count_ftt_on`],
//!   [`window_ftt_on`]) — one `match_links`, the smallest constraint driving
//!   its scan (the whole active slice when nothing is constrained); none when
//!   the descriptor is unsatisfiable. The home slot is a post-filter and
//!   narrows nothing M7 walks.
//! * [`delete_orphans_on`] — six `stab`s: three over the deleted runs, three
//!   over the retained (none when nothing is retained), and none at all for a
//!   `d` past the run budget.
//! * the lineage pair ([`in_claims_on`], [`out_claims_on`]) — one
//!   `readlink`, which answers `[]` for a non-link key and stops there;
//!   otherwise one `match_links` at a one-span query and one `type_slice`,
//!   then one `readlink` and one `is_active` per claim the home rule admits.
//! * the pointwise pair — no store walk: one `followlink` ([`project_on`]),
//!   or one `readlink` and one `is_active`
//!   ([`addressably_discoverable_from_on`]), plus M5's runs of `d`'s reading
//!   surface and ONE JOIN of the link's coverage against them, held to
//!   `MAX_IMAGE_RUNS²` span tests: M5's `project` of one slot against the
//!   content runs, or the touch test of every slot's every span against
//!   every run, each test rebuilding both spans' endpoints.
//!
//! A window computes its family's whole candidate set before it cuts,
//! whatever `n` and wherever the cursor: paging bounds the answer, never the
//! work.
//!
//! ## Boundary — deliberately NOT owned here
//!
//! * the spanfilade / coverage index, the per-slot matcher, and the
//!   AND-of-ORs combiner — M7's `stab`/`match_links`/`type_slice`
//!   (Conflicts #1); `coverage(a, i)` is NOT re-exposed — it is exactly M7's
//!   `followlink(a, i)`;
//! * content bytes (M4); provenance R and every R-keyed query —
//!   SHOWDELETIONS / FINDDOCSCONTAINING are M6's; the global-ghost / LP17
//!   determination (M6 escalation);
//! * contextual claim discovery (EL11a) and the link-subspace positional
//!   projection — composed above M8; M7's BH3 is typed target→sources
//!   lookup, not V-position projection;
//! * M5's edit path — `delete_orphans` is a pure what-if; M8 mints and
//!   writes nothing;
//! * M9 is fenced off (ASN-0129): it reads its PL surface straight from M7,
//!   never through M8.
//!
//! ## Composition
//!
//! M8 owns no `WorldState` slice, no journal record, no fold, and no
//! lock-key space tag; it contributes nothing to the assembled `World` and
//! names neither `World` nor `Record` — a pure consumer of
//! [`DiscoveryWorld`], generic over `W` (Engine Composition Contract).
//! Consumed only by M10, which reaches every read through the pure `*_on`
//! twins: M10 pins ONE snapshot per request, reports its position as
//! `as_of`, and answers at the request's reader class — none of which the
//! self-snapshotting [`LinkQuery`] handle can serve, since its snapshot is
//! taken and dropped inside the call, so the answer could not be labelled
//! with the state it came from, and it names no reader class. The handle
//! serves callers reading current state without naming it, under the total
//! predicate.
//!
//! The twins are free functions over a borrowed `&Snapshot<W>` — the dialect
//! M1, M4 and M5 use for pure reads over borrowed state, and the one that
//! keeps the snapshot the caller's to name. Nothing is bound to a snapshot
//! here, so nothing has a coordinate of its own to disagree with M10's
//! `as_of`.

#![forbid(unsafe_code)]

mod descriptor;
mod handle;
mod helpers;
mod lineage;
mod pointwise;
mod region;
mod survival;
mod types;

pub use descriptor::{count_ftt_on, findlinks_ftt_on, window_ftt_on};
pub use handle::LinkQuery;
pub use lineage::{in_claims_on, out_claims_on};
pub use pointwise::{addressably_discoverable_from_on, project_on};
pub use region::{
    content_vspan, count_v_on, findlinks_v_on, image_on, retrieve_endsets_on, window_v_on,
    MAX_ENDSET_SPANS, MAX_IMAGE_RUNS,
};
pub use survival::delete_orphans_on;
pub use types::{
    Cursor, FourSet, OrphanError, OrphanReport, QueryError, SlotSpec, SupClaim, Window,
};
// The 1-based standard slot numerals every query here indexes by, re-exported
// from the store that owns them so M8 and M7 index one set of values.
pub use skep_links::{FROM, TO, TYPE};

use skep_arrangement::HasM5;
use skep_kernel::WorldState;
use skep_links::HasLinks;
use skep_namespace::HasM3;

/// The world bound M8 reads under: three upstream slices, none of its own
/// (Engine Composition Contract — M8 contributes no slice, no record variant,
/// no accessor trait, no fold). Named for the reason M6 names
/// `RetrievalWorld` and M7 `LinkWorld`: one word for the seam, so a consumer
/// generic over the same world writes one bound rather than four.
/// Blanket-implemented, so an engine that implements the accessors gets it
/// for free.
///
/// Every read here carries the whole bound, the descriptor and lineage
/// families included, though those reach only the link store: M8 declares ONE
/// dependency surface, so widening a read later is an edit inside this crate
/// rather than a break for a caller who wrote the narrower form.
pub trait DiscoveryWorld: WorldState + HasLinks + HasM5 + HasM3 {}
impl<W: WorldState + HasLinks + HasM5 + HasM3> DiscoveryWorld for W {}

/// The auto traits M8 promises without saying. Every answer type here crosses
/// into M10's `Response` and from there onto a worker thread, and no signature
/// in this crate states it — [`FourSet`]/[`SlotSpec`] keep the promise through
/// M7's `im`-backed `Endset`, and this crate's manifest names `im` too, so a
/// swap to the `Rc`-backed `im-rc` would revoke it with nothing here failing
/// to build. This is where that fails to compile instead.
///
/// [`Cursor`] is an alias for `Option<Address>` — M1's promise, not M8's — and
/// [`LinkQuery`] is generic over `W` and borrows the kernel, so it is neither
/// `'static` nor a concrete witness to assert.
const _: fn() = || {
    fn owed<T: Send + Sync + 'static>() {}
    owed::<FourSet>();
    owed::<SlotSpec>();
    owed::<Window>();
    owed::<SupClaim>();
    owed::<OrphanReport>();
    // Both rejections too: a caller that boxes one meets
    // `Box<dyn Error + Send + Sync>`, which is the crossing form.
    owed::<QueryError>();
    owed::<OrphanError>();
};
