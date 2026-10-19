//! The spanfilade (§6): the per-slot coverage index `stab` answers from.
//!
//! [`Spanfilade`] holds one [`SlotIndex`] per slot position a stored link has,
//! and the hint fold files every span of every slot there under the link that
//! holds it. A stab asks the index which links' slot overlaps a query instead
//! of testing every link in the store, so it costs its probes and its hits;
//! the store's size enters only as the logarithm inside each ordered-set
//! range.
//!
//! Overlap is [`overlaps`], which comes to `max start < min reach`. For a
//! stored span `[s, r)` and a query span `[q, e)` that is `s < e ∧ q < r`, and
//! splitting on the stored start gives two halves that never meet and together
//! hold every match: a span with `s ≥ q` overlaps exactly when it starts inside
//! the query span, and one with `s < q` exactly when it contains `q`.
//!
//! The index answers both halves for the spans the write paths store, the
//! sibling runs: a level-uniform span whose width is zero in every component
//! but its last, `[p·x, p·y)` — the subtrees of the siblings `p·x … p·(y−1)`
//! of its axis `p`, the start less its last component. `enc` builds them, as
//! `subtree_of`'s width is `δ(1, #p)`, and so does M5's `Run::iextent`. A
//! sibling run contains a tumbler `t` exactly when `p` is a proper prefix of
//! `t` and `x ≤ t[#p] < y`, so "contains `q`" is a one-coordinate stabbing
//! question asked on each prefix of `q` that is an axis. Any other span is
//! residue, tested whole against every query span; no deposit path the wire
//! reaches stores one.
//!
//! **The axis index.** Each sibling run on an axis is filed at one node of
//! its coordinates' binary partition: its level `ℓ = bits(x ⊕ (y − 1))`,
//! which is 0 for a width-1 run, and its block `m = x >> ℓ`. A level-0 node
//! holds only `[m, m + 1)`; a node at level `ℓ ≥ 1` holds only runs inside its
//! block `[m·2^ℓ, (m + 1)·2^ℓ)` that contain both `M − 1` and its midpoint
//! `M = m·2^ℓ + 2^(ℓ−1)`, and files each twice, by `x` and by `y`. A point `c`
//! meets one node per level, `(ℓ, c >> ℓ)`. At level 0 everything there
//! contains it; above, a point below the midpoint (bit `ℓ − 1` of `c` clear) is
//! contained by the runs with `x ≤ c`, and one at or past it by the runs with
//! `y > c`. On the query start's own axis a run with `x = c` starts at the
//! query start, which the first half holds, so there the second half takes
//! `x < c` and skips level 0, and each hit is visited once.

use std::collections::BTreeSet;
use std::ops::Bound::{Excluded, Included};
use std::sync::{Arc, LazyLock};

use im::{OrdMap, OrdSet, Vector};
use skep_address::{classify_spans, Nat, Span, SpanRel, Tumbler};

use crate::endset::{Endset, Link};

/// Returns whether two spans overlap, as the spanfilade counts it (§6).
///
/// Overlap is `ProperOverlap | Containment | Equal` — not `Adjacent`
/// (abutting spans share no tumbler; matching them would false-positive every
/// link whose slot coverage merely abuts the query) and never M1's
/// `intersect` (which faults on the mixed-length endpoints M5's resolve runs
/// routinely produce). [`Spanfilade::stab`] answers by it — its two halves
/// split it on the stored start, and it tests the residue directly — and so
/// does every later conjunct of `match_links`.
pub(super) fn overlaps(a: &Span, b: &Span) -> bool {
    matches!(
        classify_spans(a, b),
        SpanRel::ProperOverlap | SpanRel::Containment | SpanRel::Equal
    )
}

/// An axis: a sibling run's start less its last component.
///
/// A [`SlotIndex`] holds each one once, and every filing on it shares that
/// allocation.
type Axis = Arc<[Nat]>;

/// One filing of a sibling run: `(axis, level, coordinate, link)`.
type Filing = (Axis, u64, Nat, Arc<Tumbler>);

/// `[0]`, the least tumbler and so below every link address.
///
/// It closes the ranges over keys that end in a link.
static BELOW_EVERY_LINK: LazyLock<Arc<Tumbler>> =
    LazyLock::new(|| Arc::new(Tumbler::new([Nat::from(0u32)]).expect("one component")));

/// Returns [`BELOW_EVERY_LINK`], shared rather than built per range.
fn below_every_link() -> Arc<Tumbler> {
    Arc::clone(&BELOW_EVERY_LINK)
}

/// The spanfilade: one [`SlotIndex`] per slot position a stored link has.
///
/// The hint fold files every span of a deposit here ([`Spanfilade::file`]),
/// so the index covers the audit slice; a read applies its view to the
/// answer.
#[derive(Debug, Clone, Default)]
pub(super) struct Spanfilade {
    /// Slot `i + 1`'s index at position `i`, for the widest arity filed.
    slots: Vec<SlotIndex>,
}

impl Spanfilade {
    /// Files every span of `value`'s slots under the link at `addr`.
    ///
    /// It costs a few ordered-set inserts per span, `O(log n)` each.
    pub(super) fn file(&mut self, addr: &Tumbler, value: &Link) {
        let link = Arc::new(addr.clone());
        for (position, endset) in value.slots().enumerate() {
            if position == self.slots.len() {
                self.slots.push(SlotIndex::default());
            }
            for span in endset.spans() {
                self.slots[position].file(&link, span);
            }
        }
    }

    /// Returns the links whose coverage at `slot` overlaps `query`.
    ///
    /// They are exactly the filed links some span of whose `slot` [`overlaps`]
    /// some span of `query`. A slot no filed link has — `0`, below the 1-based
    /// floor, or one past every arity filed — answers none, as an empty query
    /// does.
    pub(super) fn stab(&self, slot: usize, query: &Endset) -> BTreeSet<&Tumbler> {
        let mut hits = BTreeSet::new();
        if let Some(index) = slot
            .checked_sub(1)
            .and_then(|position| self.slots.get(position))
        {
            for q in query.spans() {
                index.stab(q, &mut hits);
            }
        }
        hits
    }
}

/// One slot position's index.
///
/// Its sibling runs are held twice — by start, for the half of a stab that
/// starts inside the query span, and on their axis, for the half that
/// contains the query start — and every other span once, as residue. Each
/// part is one ordered set keyed by a tuple, never a set per start or per
/// axis: `im` allocates a whole B-tree node for every set, however few keys it
/// holds. Starts and links are shared `Arc`s, so the path copies a persistent
/// insert makes copy pointers rather than tumblers.
#[derive(Debug, Clone, Default)]
struct SlotIndex {
    /// Every sibling run's start beside its link, in T1 order.
    starts: OrdSet<(Arc<Tumbler>, Arc<Tumbler>)>,
    /// Every axis a run here sits on, held once.
    axes: OrdMap<Axis, ()>,
    /// Every level an axis files a run at, as `(axis, level)`.
    levels: OrdSet<(Axis, u64)>,
    /// Every sibling run by its first coordinate `x`.
    by_first: OrdSet<Filing>,
    /// Every sibling run at level 1 or more by its end coordinate `y`.
    by_end: OrdSet<Filing>,
    /// Every span that is no sibling run, beside its link.
    residue: Vector<(Arc<Tumbler>, Span)>,
}

impl SlotIndex {
    /// Files one span of `link`'s slot.
    fn file(&mut self, link: &Arc<Tumbler>, span: &Span) {
        let Some(SiblingRun { axis, first, end }) = SiblingRun::of(span) else {
            self.residue.push_back((Arc::clone(link), span.clone()));
            return;
        };
        let level = (&first ^ &(&end - 1u32)).bits();
        let axis = self.intern(axis);
        self.starts
            .insert((Arc::new(span.start().clone()), Arc::clone(link)));
        // Asked first because an insert copies its path even when the key is
        // there, and nearly every filing meets its axis's level already held.
        let axis_level = (Arc::clone(&axis), level);
        if !self.levels.contains(&axis_level) {
            self.levels.insert(axis_level);
        }
        if level > 0 {
            self.by_end
                .insert((Arc::clone(&axis), level, end, Arc::clone(link)));
        }
        self.by_first.insert((axis, level, first, Arc::clone(link)));
    }

    /// Returns the held axis equal to `comps`, holding it first if it is new.
    fn intern(&mut self, comps: Vec<Nat>) -> Axis {
        if let Some((axis, ())) = self.axes.get_key_value(comps.as_slice()) {
            return Arc::clone(axis);
        }
        let axis: Axis = Arc::from(comps);
        self.axes.insert(Arc::clone(&axis), ());
        axis
    }

    /// Adds every link one of whose spans here overlaps `q` to `hits`.
    fn stab<'a>(&'a self, q: &Span, hits: &mut BTreeSet<&'a Tumbler>) {
        self.starting_inside(q, hits);
        self.containing(q.start(), hits);
        for (link, span) in &self.residue {
            if overlaps(q, span) {
                hits.insert(link);
            }
        }
    }

    /// Adds the link of every sibling run starting inside `q` to `hits`.
    fn starting_inside<'a>(&'a self, q: &Span, hits: &mut BTreeSet<&'a Tumbler>) {
        let from = (Arc::new(q.start().clone()), below_every_link());
        let to = (Arc::new(q.reach()), below_every_link());
        for (_, link) in self.starts.range((Included(from), Excluded(to))) {
            hits.insert(link);
        }
    }

    /// Adds the link of every sibling run that contains `start` to `hits`.
    ///
    /// A run starting at `start` itself is left to
    /// [`SlotIndex::starting_inside`].
    fn containing<'a>(&'a self, start: &Tumbler, hits: &mut BTreeSet<&'a Tumbler>) {
        let comps: Vec<Nat> = start.iter().cloned().collect();
        for (depth, c) in comps.iter().enumerate() {
            let Some((axis, ())) = self.axes.get_key_value(&comps[..depth]) else {
                continue;
            };
            let own_axis = depth + 1 == comps.len();
            let levels = (
                Included((Arc::clone(axis), 0)),
                Included((Arc::clone(axis), u64::MAX)),
            );
            for &(_, level) in self.levels.range(levels) {
                if level == 0 {
                    if !own_axis {
                        collect(&self.by_first, axis, 0, c.clone(), c + 1u32, hits);
                    }
                } else if c.bit(level - 1) {
                    let block_end = ((c >> level) + 1u32) << level;
                    collect(&self.by_end, axis, level, c + 1u32, block_end + 1u32, hits);
                } else {
                    let block_start = (c >> level) << level;
                    let past = if own_axis { c.clone() } else { c + 1u32 };
                    collect(&self.by_first, axis, level, block_start, past, hits);
                }
            }
        }
    }
}

/// Adds to `hits` every filing's link on `axis` at `level` in `[from, to)`.
fn collect<'a>(
    filings: &'a OrdSet<Filing>,
    axis: &Axis,
    level: u64,
    from: Nat,
    to: Nat,
    hits: &mut BTreeSet<&'a Tumbler>,
) {
    let from = (Arc::clone(axis), level, from, below_every_link());
    let to = (Arc::clone(axis), level, to, below_every_link());
    for (_, _, _, link) in filings.range((Included(from), Excluded(to))) {
        hits.insert(link);
    }
}

/// A sibling run `[p·x, p·y)`, as its axis `p` and its coordinates.
struct SiblingRun {
    axis: Vec<Nat>,
    first: Nat,
    end: Nat,
}

impl SiblingRun {
    /// Returns `span`'s parts if it is a sibling run, else `None`.
    ///
    /// A sibling run is level-uniform with a width zero in every component
    /// but its last. T12 makes that last component nonzero, so `y > x`.
    fn of(span: &Span) -> Option<SiblingRun> {
        let (start, width) = (span.start(), span.width());
        if start.len() != width.len() {
            return None;
        }
        let mut widths = width.iter();
        let step = widths.next_back().expect("a tumbler is nonempty");
        if widths.any(|w| w.bits() != 0) {
            return None;
        }
        let mut axis: Vec<Nat> = start.iter().cloned().collect();
        let first = axis.pop().expect("a tumbler is nonempty");
        let end = &first + step;
        Some(SiblingRun { axis, first, end })
    }
}

#[cfg(test)]
mod tests {
    use skep_address::subtree_of;

    use super::*;

    fn tumbler(comps: impl IntoIterator<Item = Nat>) -> Tumbler {
        Tumbler::new(comps).expect("test tumblers are nonempty")
    }

    /// Returns the axis every run below sits on, `[1, 0, 1]`, plus `tail`.
    fn on_axis(tail: &[&Nat]) -> Tumbler {
        let axis = [1u32, 0, 1].map(Nat::from);
        tumbler(axis.into_iter().chain(tail.iter().map(|&c| c.clone())))
    }

    /// Returns whether a stab of `index` with the one span `query` answers.
    fn found(index: &SlotIndex, query: &Span) -> bool {
        let mut hits = BTreeSet::new();
        index.stab(query, &mut hits);
        !hits.is_empty()
    }

    #[test]
    fn a_sibling_run_is_found_at_exactly_the_points_it_contains() {
        // Every run [x, y) with x < y ≤ 70, filed alone, against every point
        // c < 72: at the point's own subtree, which the run starts in or
        // contains, and beneath it, where only the containing half can see
        // it. Runs reach level 7 and cross every power of two up to 64. The
        // second grid straddles 2^64, where the coordinates take two digits
        // and a run crossing 2^64 files at level 65.
        let link = Arc::new(tumbler([Nat::from(9u32)]));
        let beneath_tail = Nat::from(5u32);
        for (offset, size) in [
            (Nat::from(0u32), 70u32),
            ((Nat::from(1u32) << 64u32) - 12u32, 24),
        ] {
            let probes: Vec<(Nat, Span, Span)> = (0..size + 2)
                .map(|c| {
                    let point = &offset + c;
                    let at = subtree_of(&on_axis(&[&point]));
                    let beneath = subtree_of(&on_axis(&[&point, &beneath_tail]));
                    (point, at, beneath)
                })
                .collect();
            for x in 0..size {
                for y in x + 1..=size {
                    let (first, end) = (&offset + x, &offset + y);
                    let run = Span::from_endpoints(on_axis(&[&first]), &on_axis(&[&end]))
                        .expect("x < y at one length");
                    let mut index = SlotIndex::default();
                    index.file(&link, &run);
                    for (point, at, beneath) in &probes {
                        let inside = first <= *point && *point < end;
                        assert_eq!(found(&index, at), inside, "[{first}, {end}) at {point}");
                        assert_eq!(
                            found(&index, beneath),
                            inside,
                            "[{first}, {end}) beneath {point}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_spans_the_write_paths_store_are_sibling_runs() {
        // `enc`'s unit-depth spans at every depth, a one-component one
        // included, and an extent M5's `Run::iextent` builds.
        for comps in [&[1u32][..], &[1, 0, 1], &[1, 0, 1, 0, 1, 0, 2, 7]] {
            let t = tumbler(comps.iter().map(|&c| Nat::from(c)));
            assert!(SiblingRun::of(&subtree_of(&t)).is_some(), "{t}");
        }
        let extent =
            Span::from_endpoints(on_axis(&[&Nat::from(3u32)]), &on_axis(&[&Nat::from(9u32)]))
                .expect("an extent");
        let run = SiblingRun::of(&extent).expect("an extent is a sibling run");
        assert_eq!((run.first, run.end), (Nat::from(3u32), Nat::from(9u32)));
    }

    #[test]
    fn a_span_that_is_no_sibling_run_is_tested_whole() {
        // `[1,0,1,5] + [0,0,1,3]` reaches `[1,0,2,3]`: its width is nonzero
        // ahead of its last component, so it is no sibling run, and neither is
        // a span whose width is longer than its start.
        let n = |c: u32| Nat::from(c);
        let span = Span::new(tumbler([1, 0, 1, 5].map(n)), tumbler([0, 0, 1, 3].map(n)))
            .expect("T12 admits it");
        let skew =
            Span::new(tumbler([5, 3].map(n)), tumbler([0, 2, 7].map(n))).expect("T12 admits it");
        assert!(SiblingRun::of(&span).is_none());
        assert!(SiblingRun::of(&skew).is_none());
        let link = Arc::new(tumbler([n(9)]));
        let mut index = SlotIndex::default();
        index.file(&link, &span);
        let at = |comps: &[u32]| {
            let probe = subtree_of(&tumbler(comps.iter().map(|&c| n(c))));
            found(&index, &probe)
        };
        assert!(at(&[1, 0, 1, 5]), "at its start");
        assert!(at(&[1, 0, 1, 9]), "past its start, on its start's axis");
        assert!(at(&[1, 0, 2, 2]), "on the next axis, short of its reach");
        assert!(!at(&[1, 0, 1, 4]), "abutting its start");
        assert!(!at(&[1, 0, 2, 3]), "abutting its reach");
        assert!(!at(&[1, 0, 1, 4, 7]), "beneath a tumbler short of it");
    }
}
