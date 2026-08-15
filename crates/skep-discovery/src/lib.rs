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
//! `View::Active`, so results are *foundation ∩ active* and a nullified link
//! never surfaces (Conflicts #8 — a deliberate divergence from the unfiltered
//! foundations of ASN-0127/0098/0108/0117). Windowing (ASN-0108) is a
//! stateless key-cut over M7's native `OrdSet<Tumbler>` — address order IS
//! the permanent enumeration key (Conflicts #3), so the cursor survives
//! orphaning and M8 pages with no index of its own.
//!
//! M8 does almost no span algebra — and never the level-gated kind:
//! coverage-overlap matching goes through M7, I→V through M5, query endsets
//! through `Run::iextent` + `Endset::from_spans`; the lone pointwise span
//! comparison is `discoverable_from`'s level-gate-free `classify_spans`
//! touch test (§5).
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
//! `HasLinks + HasM5 + HasM3`, generic over `W` (Engine Composition
//! Contract). Consumed only by M10, which uses the [`LinkQuery`] handle for
//! single reads and the pure `*_on` twins over one shared `Snapshot` for any
//! multi-call verdict (the ASN-0132 snapshot-token need; M2 clause 6).

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
pub use pointwise::{discoverable_from_on, project_on};
pub use region::{count_v_on, findlinks_v_on, image_on, retrieve_endsets_on, window_v_on};
pub use survival::delete_orphans_on;
pub use types::{Cursor, FourSet, OrphanReport, QueryError, SlotSpec, SupClaim, Window};

/// FROM = 1 — the 1-based standard slot (M7's convention).
pub const FROM: usize = 1;

/// TO = 2 — the 1-based standard slot (M7's convention).
pub const TO: usize = 2;

/// TYPE = 3 — the 1-based standard slot (M7's convention).
pub const TYPE: usize = 3;
