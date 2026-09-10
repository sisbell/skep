//! §Internal design — the shared free helpers every family composes: the
//! run-set stab that turns an arrangement image into matched links, the home
//! attribution and the home rule built on it, and the one windowing
//! combinator. All pure over borrowed state; nothing here snapshots (callers
//! thread ONE snapshot per operation).
//!
//! Every read walks M7's `OrdSet`s by reference — `iter`, `range`,
//! `contains` — and clones only the addresses it hands back. `im` 15's
//! consuming iterator is not a move: it copies every node it passes and clones
//! every value it yields, so `into_iter` over a set a read only looks at
//! copies the set; and `im`'s `intersection` and `relative_complement` walk
//! their ARGUMENT that way, so a large set belongs on the `contains` side of a
//! filter, never on the walked side. [`union_slots`] is the one consuming set
//! operation kept, and says why.

use std::ops::Bound::{Excluded, Unbounded};

use im::OrdSet;
use skep_address::{document_of, Address};
use skep_arrangement::Run;
use skep_links::{Endset, LinkState, View};

use crate::types::{Cursor, Window};
use crate::{FROM, TO, TYPE};

/// The slots a v1 link has: every v1 link-creation path deposits an arity-3
/// link, so a disjunction over these three is exact over ALL slots and a
/// per-slot read misses nothing (§1). Nothing in M8 can check that — `stab`
/// is per-slot and M8 owns no index — so it is stated once, here, and every
/// slot-indexed read reaches the store through this list.
pub(crate) const V1_SLOTS: [usize; 3] = [FROM, TO, TYPE];

/// The links whose coverage overlaps `runs`, PAIRED with the slot each set
/// was stabbed at and kept SEPARATE (slot attribution reads them — §4), so
/// no consumer re-derives which position means which numeral.
/// `View::Active` discharges addressability — nullified links never match.
///
/// The lift from arrangement runs to M7's query `Endset` lives here, so every
/// region-shaped query reaches the spanfilade through one reading of its
/// I-extents. That endset aggregates iextents across origin documents and is
/// therefore MIXED-LENGTH by construction; no partition by level class is
/// owed because its only consumer is M7's `classify_spans` overlap, which is
/// gate-free — any level-gated operation added here (normalizing the query,
/// keying a cache on `canonical_key`) would owe the partition `Run::iextent`
/// names. Empty `runs` skip the store: M7 answers `stab(slot, ⟨⟩, ·) = ∅`
/// for the endset they lift to, so the short-circuit saves a scan rather than
/// changing an answer.
pub(crate) fn stab_runs_by_slot(l: &LinkState, runs: &[Run]) -> [(usize, OrdSet<Address>); 3] {
    if runs.is_empty() {
        return V1_SLOTS.map(|i| (i, OrdSet::new()));
    }
    let q = Endset::from_spans(runs.iter().map(Run::iextent)); // coverage(q) = the runs
    V1_SLOTS.map(|i| (i, l.stab(i, &q, View::Active)))
}

/// The disjunctive ASN-0127 `findlinks(I)` core: OR across a v1 link's slots
/// (M7 has no slot-collapsed primitive).
///
/// The one consuming set operation a read keeps, because its answer IS a new
/// set: `im`'s `union` keeps its larger operand and inserts the smaller into
/// it, so at every step the larger side is carried over with its untouched
/// nodes shared, never rebuilt, and only the smaller is walked — through
/// `im`'s consuming iterator, which clones what it yields — and path-copied
/// in where it lands. It costs least when one slot dominates; gathering the
/// union from three borrowed walks instead would copy every member of all
/// three.
pub(crate) fn union_slots(by_slot: &[(usize, OrdSet<Address>); 3]) -> OrdSet<Address> {
    by_slot
        .iter()
        .fold(OrdSet::new(), |acc, (_, hits)| acc.union(hits.clone()))
}

/// `findlinks(coverage of runs)` ∩ the active view, as M7's native
/// `OrdSet<Address>` (address order — ASN-0108's permanent enumeration key):
/// the selection index every run-anchored family reads.
pub(crate) fn stab_runs(l: &LinkState, runs: &[Run]) -> OrdSet<Address> {
    union_slots(&stab_runs_by_slot(l, runs))
}

/// `home(a)`: the origin Document of a link address — M1's `document_of`
/// projection (EL8b), spelled once so the descriptor family's home filter and
/// the lineage read-out attribute a link the same way.
pub(crate) fn home_of(a: &Address) -> Address {
    document_of(a).expect("a link address has zeros = 3, so its origin Document exists")
}

/// THE HOME RULE (§3, PUB-6.13): may the reader read `a`'s home? The home
/// projection composed with the caller's predicate, in one place, because
/// `readable` answers about a DOCUMENT and every question the rule answers
/// here is asked about a LINK. Asked directly of the link it would answer
/// TRUE: an element address is absent from the publication index exactly as
/// a published document is, so the rule would admit every link. That is why
/// the composition is an element and not an idiom.
///
/// Total on every address, because the pointwise pair asks it of a
/// caller's `a` before anything establishes that `a` is a link: an address
/// with no document field — a node or an account — lives under no home and
/// has nothing to withhold, so the rule admits it and the store's own answer
/// about it stands. Every link has a home, so on a result set this is
/// exactly `readable(home(a))`.
pub(crate) fn home_readable(readable: &dyn Fn(&Address) -> bool, a: &Address) -> bool {
    document_of(a).is_none_or(|home| readable(&home))
}

/// The one windowing combinator (ASN-0108) driving both `window_v` and
/// `window_ftt`: a stateless key-cut over `candidates` in address order,
/// admitting those `keep` accepts.
///
/// * Resume is `range(Excluded(cursor)..)` — a key-cut, never an exact-match
///   scan, so the cursor survives orphaning by construction (W8), and no
///   continuously-matching link is duplicated or skipped (W4/W5).
/// * `n` is clamped to ≥ 1 (W9 totality): an unclamped `n = 0` would yield
///   `exhausted = (0 < 0) = false` with an empty batch and an unchanged
///   cursor — a silent non-terminating signal.
/// * `keep` is the caller's post-filter over the candidate set — the FTT
///   residence test, the home rule both families carry, or their
///   conjunction — applied LAZILY during the range walk, so a link the home
///   rule or the residence test refuses is skipped BEFORE the slice and never
///   counted against `n` (PUB-6.14), and a narrow query never materializes
///   the filtered set.
/// * `exhausted = batch.len() < n` (a short window, zero included, W9);
///   `next` = the ≺-max of the batch, else the cursor unchanged.
pub(crate) fn window_over(
    candidates: &OrdSet<Address>,
    cur: Cursor,
    n: usize,
    keep: impl Fn(&Address) -> bool,
) -> Window {
    let n = n.max(1);
    let lo = match &cur {
        None => Unbounded,
        Some(c) => Excluded(c.clone()),
    };
    let batch: Vec<Address> = candidates
        .range((lo, Unbounded))
        .filter(|a| keep(a)) // a: &&Address → deref to &Address
        .take(n)
        .cloned()
        .collect();
    let next = batch.last().cloned().or(cur);
    Window {
        exhausted: batch.len() < n,
        batch,
        next,
    }
}
