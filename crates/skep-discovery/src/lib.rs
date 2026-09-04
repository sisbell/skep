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
//! (Conflicts #8 — a deliberate divergence from the unfiltered foundations of
//! ASN-0127/0108). `delete_orphans` and
//! [`addressably_discoverable_from_on`] narrow the same way, the latter
//! diverging from ASN-0117/0098 by conjoining `is_active` onto LP12
//! discoverability.
//!
//! Two reads depart from that, and a caller building a live-links view needs
//! both:
//!
//! * [`project_on`] is UNFILTERED — coverage reaches it through M7's
//!   `followlink`, which takes no `View` and reports what is recorded, so a
//!   retracted link still projects the V-positions it covers. That is
//!   ASN-0098's `project` unchanged; the addressable-narrowed question it
//!   looks like it answers is [`addressably_discoverable_from_on`]'s.
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
//! M8 does almost no span algebra — and never the level-gated kind:
//! coverage-overlap matching goes through M7, I→V through M5, query endsets
//! through `Run::iextent` + `Endset::from_spans`; the lone pointwise span
//! comparison is `addressably_discoverable_from`'s level-gate-free
//! `classify_spans` touch test (§5).
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
//! Contract). Consumed only by M10, which reaches every read through the pure
//! `*_on` twins: M10 pins ONE snapshot per request and reports its position
//! as `as_of`, which the self-snapshotting [`LinkQuery`] handle cannot serve
//! — its snapshot is taken and dropped inside the call, so the answer could
//! not be labelled with the state it came from. The handle serves callers
//! reading current state without naming it.

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
};
pub use survival::delete_orphans_on;
pub use types::{
    Cursor, FourSet, OrphanError, OrphanReport, QueryError, SlotSpec, SupClaim, Window,
};
// The 1-based standard slot numerals every query here indexes by, re-exported
// from the store that owns them so M8 and M7 index one set of values.
pub use skep_links::{FROM, TO, TYPE};
