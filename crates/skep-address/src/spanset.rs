//! Span-sets, their canonical normalization and the set-level algebra (§G).
//!
//! A span-set is the union-denoting collection (ASN-0053: S0, S7–S11, N1/N2).
//! The algebra is interval arithmetic over a hierarchical ordered space — not
//! finite-set manipulation, not byte counting: every span denotes an infinite
//! set (deeper sub-extensions fill every interval), which is why no span-set
//! denotes an arbitrary finite point set exactly (S7's binding fact).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::arithmetic::next_at_length;
use crate::error::LevelMismatch;
use crate::span::{intersection, separated, subtree_of, Endpoints, Span};
use crate::tumbler::Tumbler;

/// A union-denoting sequence of component spans (`⟦Σ⟧ = ⋃ ⟦σᵢ⟧`).
///
/// Order-independence is a property of the *denotation* (S10, and only up to
/// the canonical form), never of the value: component spans keep their stored
/// order, and the raw `Eq` below distinguishes it.
///
/// Raw `PartialEq`/`Eq`/`Hash` are **structural** — they distinguish
/// un-normalized forms and are not denotational identity. The denotational,
/// content-addressed identity is [`CanonicalForm`] (S9); use that as a
/// dedup/cache key, never a raw `SpanSet`.
///
/// Backing (design default): `im::Vector<Span>` — structural sharing makes a
/// clone or a [`union`] a new value cheaply sharing the old, exactly the
/// cheap-versioned-immutable-value shape wanted here (this is where `im`
/// earns its keep, not on the tumbler). Serde: both sides derived — raw
/// `SpanSet` carries no standing invariant (un-normalized is legal), and the
/// component spans serialize and validate through `Span`'s own symmetric
/// shadows, so the round-trip guarantee is inherited.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpanSet(im::Vector<Span>);

/// The unique normalized form (S9) as a content-addressed identity.
///
/// It is `Hash + Eq`, so it serves directly as M7's *in-memory* dedup/cache
/// key (M7 hashes it, inside its dedup key, into a `HashMap`; a hash collision
/// is harmless because the dedup *decision* compares by `Eq`). No `LockKey`
/// carries one: the dedup lock sections serialize address-denoting classes
/// only.
///
/// It is deliberately not `Serialize`/`Deserialize` (the documented default):
/// the dedup key lives in memory and is rebuilt by replay, never journaled.
/// If M7 ever journals or checkpoints it, add a symmetric `into`/`try_from =
/// "SpanSet"` shadow pair whose deserialize side re-establishes
/// `is_normalized` — the same no-unguarded-mint rule as
/// `Tumbler`/`Address`/`Span`.
///
/// Invariant: the inner `SpanSet` is normalized (construction is gated on
/// [`canonical_key`]; no mutable access exists).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalForm(SpanSet);

impl CanonicalForm {
    /// Returns a read-only view of the normalized inner set.
    ///
    /// The invariant is preserved. This is what a collision-free `LockKey` or
    /// a future serialization would read; M7's coverage-class policy composes
    /// its per-class canonical forms as whole values, without reading through
    /// it.
    pub fn as_set(&self) -> &SpanSet {
        &self.0
    }
}

impl SpanSet {
    /// Returns `⟨⟩ ≜ ∅`, the empty designation.
    ///
    /// It is structurally distinct from any zero-width span (which the span
    /// constructor rejects, T12/S2).
    pub fn empty() -> SpanSet {
        SpanSet(im::Vector::new())
    }

    /// Returns `⟨σ⟩`, the one-span set.
    ///
    /// No gate and no normalization: like [`FromIterator`], it takes the span
    /// as given, so a non-level-uniform span is admitted here and refused
    /// later by the first operation that needs the class. This is how
    /// [`crate::difference`] returns its separated, adjacent and overlap
    /// cases, and how a caller lifts a single span — a run's I-extent, one
    /// span of an endset — into the set algebra.
    pub fn singleton(s: Span) -> SpanSet {
        SpanSet(im::Vector::unit(s))
    }

    /// Returns `|Σ|`, the component-span count.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `len() == 0`, which holds iff the set is `⟨⟩`.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the component spans in *stored* order.
    ///
    /// The order is N1 ascending starts when normalized, insertion order
    /// otherwise — a structural view, like the raw `Eq`/`Hash`. This is the
    /// read surface downstream consumers walk: M8's projection, M6/M10 result
    /// marshaling, and `difference`'s ≤ 2-span result; M7's spanfilade walks
    /// its own endsets instead, and the RETRIEVEENDSETS answer carries those
    /// endsets. The same walk is what `&SpanSet` yields in a `for` loop;
    /// [`IntoIterator`] on the owned set moves the component spans out for a
    /// consumer that wants them.
    pub fn iter(&self) -> Spans<'_> {
        Spans(self.0.iter())
    }

    /// Returns the one endpoint length every component span shares.
    ///
    /// It is S8's *full* precondition, spelled once and answerable on demand,
    /// and `Ok(None)` for ⟨⟩. Every span-set operation that can refuse gates
    /// through this, so a caller can ask the question before it asks for the
    /// answer, and gets the same verdict either way.
    ///
    /// # Errors
    ///
    /// Returns [`LevelMismatch`] when some component span is not level-uniform
    /// (`#start ≠ #width`, without which the start↔reach arithmetic breaks) or
    /// the component spans disagree on `#start`.
    pub fn level_class(&self) -> Result<Option<usize>, LevelMismatch> {
        let Some(first) = self.0.front() else {
            return Ok(None);
        };
        let shared_length = first.start().len();
        for s in self.0.iter() {
            if !s.is_level_uniform() || s.start().len() != shared_length {
                return Err(LevelMismatch);
            }
        }
        Ok(Some(shared_length))
    }

    /// Returns the partition of the component spans by endpoint length.
    ///
    /// It is the decomposition that turns a set outside S8's domain into sets
    /// inside it, keyed by the `#start` each class shares. Total: a component
    /// span that is not level-uniform lands in its start's class and is
    /// refused there by that class's own gate, exactly as it would be here.
    ///
    /// This is the per-level-class discipline every consumer whose span-set
    /// can mix origin lengths needs — a transcluded I-coverage, a
    /// heterogeneous-length endset: partition, operate within each class,
    /// union the results. Cross-length denotational canonicalization is
    /// genuinely absent from the source algebra ([`canonical_key`]), so the
    /// partition is the whole of what M1 can offer, and offering it is
    /// better than each caller rebuilding it.
    pub fn by_level_class(&self) -> BTreeMap<usize, SpanSet> {
        let mut classes: BTreeMap<usize, Vec<Span>> = BTreeMap::new();
        for s in self.0.iter() {
            classes.entry(s.start().len()).or_default().push(s.clone());
        }
        classes
            .into_iter()
            .map(|(len, spans)| (len, spans.into_iter().collect()))
            .collect()
    }

    /// Returns the unique canonical form (S8/S9; N1 ∧ N2).
    ///
    /// It sorts by start, then makes one linear sweep coalescing every pair
    /// that is not separated; O(n log n), dominated by the sort. N2's
    /// coalescing rule *is* S3a's join rule, asked of the same `separated`
    /// predicate [`crate::merge`] asks, so the two scales cannot drift on what
    /// counts as contiguous. Pinned edge: `normalize(⟨⟩) = Ok(⟨⟩)` — S8's
    /// n = 0 case, vacuously N1 ∧ N2.
    ///
    /// # Errors
    ///
    /// Returns [`LevelMismatch`] when the set fails the full S8 precondition,
    /// [`SpanSet::level_class`], on which it is gated.
    pub fn normalize(&self) -> Result<SpanSet, LevelMismatch> {
        if self.level_class()?.is_none() {
            return Ok(SpanSet::empty());
        }
        let mut spans: Vec<Endpoints> = self.0.iter().map(Endpoints::of).collect();
        spans.sort_by(|x, y| x.start.cmp(&y.start));
        let mut out: Vec<Span> = Vec::new();
        let mut rest = spans.into_iter();
        let mut run = rest.next().expect("nonempty: level_class was Some");
        for following in rest {
            if !separated(&run, &following) {
                // overlap or adjacency — coalesce (N2)
                if following.reach > run.reach {
                    run.reach = following.reach;
                }
            } else {
                out.push(
                    run.into_span()
                        .expect("gated one-length endpoints with start < reach"),
                );
                run = following;
            }
        }
        out.push(
            run.into_span()
                .expect("gated one-length endpoints with start < reach"),
        );
        Ok(out.into_iter().collect())
    }

    /// Returns whether this set already *is* its canonical form.
    ///
    /// It is `true` for ⟨⟩ (vacuous N1 ∧ N2); a set outside S8's domain
    /// (level-mismatched) has no canonical form and answers `false`.
    pub fn is_normalized(&self) -> bool {
        match self.normalize() {
            Ok(n) => n == *self,
            Err(LevelMismatch) => false,
        }
    }

    /// Tests ⟦Σ⟧ membership: whether some component span contains `t`.
    ///
    /// ⟨⟩ denotes nothing.
    pub fn denotes(&self, t: &Tumbler) -> bool {
        self.0.iter().any(|s| s.contains(t))
    }
}

/// The general constructor: it collects the spans as given.
///
/// No normalization, no level gate, no singleton+union folding; the caller
/// normalizes.
impl FromIterator<Span> for SpanSet {
    fn from_iter<I: IntoIterator<Item = Span>>(iter: I) -> SpanSet {
        SpanSet(iter.into_iter().collect())
    }
}

/// Defaults to `⟨⟩`, the empty designation.
///
/// A span-set can then be defaulted wherever a collection is expected. It
/// delegates to [`SpanSet::empty`], which is the name the algebra's own prose
/// uses.
impl Default for SpanSet {
    fn default() -> SpanSet {
        SpanSet::empty()
    }
}

/// Borrowed component spans in stored order — the iterator `&SpanSet` walks.
///
/// Opaque, so the `im::Vector` backing decision stays the module's own.
///
/// Opacity hides the *container*, never the walk's capabilities: the reverse
/// walk, the exact length and the fused guarantee are forwarded below, so a
/// consumer sweeping a normalized set from its high end (N1 puts the greatest
/// start last) need not collect it first. `Clone` is the one capability that
/// does not reach the caller — `im`'s vector iterator is not cloneable — so a
/// caller that needs two independent cursors takes them from the set, which is.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Spans<'a>(<&'a im::Vector<Span> as IntoIterator>::IntoIter);

impl<'a> Iterator for Spans<'a> {
    type Item = &'a Span;
    fn next(&mut self) -> Option<&'a Span> {
        self.0.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl<'a> DoubleEndedIterator for Spans<'a> {
    fn next_back(&mut self) -> Option<&'a Span> {
        self.0.next_back()
    }
}

impl ExactSizeIterator for Spans<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl std::iter::FusedIterator for Spans<'_> {}

/// The cursor, not the spans.
///
/// The backing's iterator is neither `Clone` nor `Debug`, so there is no way
/// to show what is left without consuming it, and the set it came from is
/// `Debug` already. [`crate::Components`] does render its remainder, because a
/// slice iterator can be walked without being spent.
impl fmt::Debug for Spans<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Spans").finish_non_exhaustive()
    }
}

impl<'a> IntoIterator for &'a SpanSet {
    type Item = &'a Span;
    type IntoIter = Spans<'a>;
    fn into_iter(self) -> Spans<'a> {
        self.iter()
    }
}

/// Owned component spans in stored order.
///
/// They are the component spans moved out of a set the caller is finished
/// with, so a re-collection need not clone each one, unless the set still
/// shares its backing with another set, which makes the backing clone the
/// shared spans first. It carries the same reverse walk, exact length and
/// fused guarantee as [`Spans`], and withholds `Clone` for the same reason:
/// the backing's consuming iterator is not cloneable.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct IntoSpans(<im::Vector<Span> as IntoIterator>::IntoIter);

impl Iterator for IntoSpans {
    type Item = Span;
    fn next(&mut self) -> Option<Span> {
        self.0.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl DoubleEndedIterator for IntoSpans {
    fn next_back(&mut self) -> Option<Span> {
        self.0.next_back()
    }
}

impl ExactSizeIterator for IntoSpans {
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl std::iter::FusedIterator for IntoSpans {}

/// The cursor, not the spans — as for [`Spans`].
impl fmt::Debug for IntoSpans {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntoSpans").finish_non_exhaustive()
    }
}

impl IntoIterator for SpanSet {
    type Item = Span;
    type IntoIter = IntoSpans;
    fn into_iter(self) -> IntoSpans {
        IntoSpans(self.0.into_iter())
    }
}

/// Returns the ⊕-free join of `a` and `b`: concatenation only (S10).
///
/// It never normalizes, never fails (total). Commutative and associative up to
/// the canonical form, with idempotence following as a derived corollary, so
/// span-sets form a join-semilattice within one tumbler length: workers
/// accumulate and merge in any order to a deterministic canonical result,
/// coordination-free. Normalization is the caller's separate (eager or lazy)
/// step — the merge path stays union-only because difference is not
/// order-free.
#[must_use = "union returns the joined span-set; it does not modify its operands"]
pub fn union(a: &SpanSet, b: &SpanSet) -> SpanSet {
    let mut joined = a.0.clone();
    joined.append(b.0.clone());
    SpanSet(joined)
}

/// Normalizes both operands and hands them back in the sweeps' working form.
///
/// Both are confirmed mutually level-compatible, and the working form is
/// `(start, reach)` — the shared entry of the set-level sweeps, and the
/// set-level counterpart of `gated_endpoints`. Each side's own S8 gate runs
/// inside [`SpanSet::normalize`]; what remains is the cross-operand question,
/// and it arises only when both sides have a class — ⟨⟩ has none and is
/// compatible with anything. (`level_class` on an already-normalized set
/// cannot fail; the `?` is here so the gate keeps one spelling.) Like the
/// pairwise gate, the working form is obtainable only past the gate, so
/// neither sweep runs against un-normalized component spans or pays `reach()`
/// per comparison.
///
/// # Errors
///
/// Returns [`LevelMismatch`] when either set is not internally level-uniform,
/// or when both have a class and the two classes differ.
fn normalized_endpoints(
    a: &SpanSet,
    b: &SpanSet,
) -> Result<(Vec<Endpoints>, Vec<Endpoints>), LevelMismatch> {
    let (na, nb) = (a.normalize()?, b.normalize()?);
    if let (Some(la), Some(lb)) = (na.level_class()?, nb.level_class()?) {
        if la != lb {
            return Err(LevelMismatch);
        }
    }
    Ok((
        na.iter().map(Endpoints::of).collect(),
        nb.iter().map(Endpoints::of).collect(),
    ))
}

/// Intersects the two sets in one sweep-line pass over their canonical forms.
///
/// It normalizes *both* inputs internally — so the error is honest — and
/// emits a normalized result. An empty operand needs no arm of its own: the
/// sweep runs while both sides have component spans, so ⟨⟩ on either side
/// yields ⟨⟩.
///
/// # Errors
///
/// Returns [`LevelMismatch`] when a set is not internally level-uniform *or*
/// the two sets are not mutually level-compatible.
pub fn intersect_sets(a: &SpanSet, b: &SpanSet) -> Result<SpanSet, LevelMismatch> {
    let (a_spans, b_spans) = normalized_endpoints(a, b)?;
    let (mut i, mut j) = (0usize, 0usize);
    let mut out: Vec<Span> = Vec::new();
    while i < a_spans.len() && j < b_spans.len() {
        if let Some(s) = intersection(&a_spans[i], &b_spans[j]) {
            out.push(s);
        }
        if a_spans[i].reach <= b_spans[j].reach {
            i += 1;
        } else {
            j += 1;
        }
    }
    Ok(out.into_iter().collect())
}

/// Returns the set difference `⟦a⟧ \ ⟦b⟧`, one sweep over the canonical forms.
///
/// It normalizes both inputs internally and emits a normalized result. An
/// empty operand needs no arm of its own: with no a-spans the sweep emits
/// nothing (⟨⟩ \ b = ⟨⟩), and with no b-spans each a-span survives whole
/// (a \ ⟨⟩ = a).
///
/// Fan-out is `|Σ| ≤ |a| + |b|`. Two emissions exist: a *gap*, which requires
/// a b-start strictly inside the surviving part of an a-span, and a *tail*,
/// at most one per a-span. Canonical a-spans are pairwise separated, so a
/// b-start lies strictly inside at most one of them and each b-span yields at
/// most one gap; normalizing grows neither operand, so the two counts bound
/// against the inputs as given.
///
/// # Errors
///
/// Returns [`LevelMismatch`] when a set is not internally level-uniform or
/// the two sets are not mutually level-compatible.
pub fn difference_sets(a: &SpanSet, b: &SpanSet) -> Result<SpanSet, LevelMismatch> {
    let (a_spans, b_spans) = normalized_endpoints(a, b)?;
    let mut out: Vec<Span> = Vec::new();
    let mut j = 0usize;
    for a_span in a_spans {
        // b-spans wholly at-or-before this a-start can touch no later a-span
        // either (starts ascend), so this cursor advances for good.
        while j < b_spans.len() && b_spans[j].reach <= a_span.start {
            j += 1;
        }
        let mut surviving_from = a_span.start;
        let mut k = j;
        while k < b_spans.len() && b_spans[k].start < a_span.reach {
            if b_spans[k].start > surviving_from {
                out.push(
                    Span::from_endpoints(surviving_from.clone(), &b_spans[k].start)
                        .expect("one length class, survivor start below the b-start"),
                );
            }
            if b_spans[k].reach > surviving_from {
                surviving_from = b_spans[k].reach.clone();
            }
            if surviving_from >= a_span.reach {
                break;
            }
            k += 1;
        }
        if surviving_from < a_span.reach {
            out.push(
                Span::from_endpoints(surviving_from, &a_span.reach)
                    .expect("one length class, survivor start below the a-span reach"),
            );
        }
    }
    Ok(out.into_iter().collect())
}

/// Tests denotational equality by S9's oracle: normalize both, compare.
///
/// Two internally-uniform sets in *different* length classes normalize
/// independently and compare unequal — `Ok(false)`, not an error (§7;
/// denotationally sound: equal non-empty denotations share a minimum element,
/// forcing a single length class).
///
/// That is where `equiv` parts from [`intersect_sets`] and
/// [`difference_sets`], which refuse a cross-class pair outright: a caller
/// dispatching on `LevelMismatch` to decide when to partition gets no such
/// signal here, and asks [`SpanSet::level_class`] — or partitions with
/// [`SpanSet::by_level_class`] — instead.
///
/// # Errors
///
/// It inherits `normalize`'s *per-set* fallibility: [`LevelMismatch`] when
/// either set is not internally level-uniform.
pub fn equiv(a: &SpanSet, b: &SpanSet) -> Result<bool, LevelMismatch> {
    Ok(a.normalize()? == b.normalize()?)
}

/// Returns the canonical form as the denotational dedup/cache key (S9).
///
/// It is the seam M7's link-dedup coverage-class policy rides (M1 computes
/// the canonical form; M7 decides the class *policy*; M2 never computes it,
/// and none reaches M2's keyed critical section — the dedup lock keys
/// serialize address-denoting classes only). `canonical_key(⟨⟩)` succeeds
/// with the empty canonical form.
///
/// # Errors
///
/// Returns [`LevelMismatch`] when the set is not internally level-uniform. A
/// heterogeneous-length endset falls outside S8/S9 and yields it —
/// cross-length denotational canonicalization is genuinely absent from the
/// source algebra, so M7 partitions with [`SpanSet::by_level_class`] and
/// composes the per-class keys as the values of a per-length map.
pub fn canonical_key(set: &SpanSet) -> Result<CanonicalForm, LevelMismatch> {
    Ok(CanonicalForm(set.normalize()?))
}

/// Returns the single-span convex hull of a finite point set (S0).
///
/// It is `from_endpoints(min P, next_at_length(max P))`. The two ways there is
/// no hull are told apart, as they are everywhere else in the module:
/// `Ok(None)` for an empty P, which has nothing to enclose, and
/// `Err(LevelMismatch)` for the domain violation.
///
/// The reach is the *least* same-length tumbler exceeding max (TS4,
/// length-preserving) — so the hull is *tight* and the name honest; `inc(max,
/// 0)` would also cover ⊇ P but over-captures whenever `sig(max) < #max`. One
/// reach convention serves [`subtree_of`], [`cover`], and `hull` alike. The
/// `|Σ| = |P|` unit-span cover for arbitrary P (S7) is the separate
/// [`cover`], not this hull.
///
/// P is any walk over borrowed points, read once: the extremes are all this
/// needs, so a caller holding an endset, a set or a filtered view hands its
/// own iterator over rather than materializing a buffer of owned tumblers to
/// have them compared.
///
/// # Errors
///
/// Returns [`LevelMismatch`] when `#min P ≠ #max P` — the domain violation:
/// `(min P, next_at_length(max P))` puts its two endpoints in different length
/// classes and is not WF, so the tight span the name promises does not exist
/// here. Covering spans across classes do exist (WF admits the all-zero
/// sentinel as a start, TA6); none of them is a hull, which is why S0's domain
/// is one length class — not because coverage is impossible. That is the only
/// real precondition: by convexity the hull covers even a P whose *interior*
/// points mix lengths.
pub fn hull<'p>(
    points: impl IntoIterator<Item = &'p Tumbler>,
) -> Result<Option<Span>, LevelMismatch> {
    let mut points = points.into_iter();
    let Some(first) = points.next() else {
        return Ok(None); // P is empty
    };
    let (mut min_point, mut max_point) = (first, first);
    for p in points {
        if p < min_point {
            min_point = p;
        }
        if p > max_point {
            max_point = p;
        }
    }
    if min_point.len() != max_point.len() {
        return Err(LevelMismatch);
    }
    Ok(Some(
        Span::from_endpoints(min_point.clone(), &next_at_length(max_point))
            .expect("min ≤ max < next_at_length(max) at one shared length, so WF fires"),
    ))
}

/// Returns the unit-span cover of a finite point set (S7).
///
/// It is one unit span per point with S7's exact witness width `δ(1, #t)` —
/// i.e. each unit span *is* `subtree_of(t)`, so `cover` and `subtree_of` share
/// one construction — `union`-joined (concatenation). `|Σ| = |P|` and
/// `⟦Σ⟧ ⊇ P` — a *cover*, not exact (S7's binding fact: no span-set denotes
/// an arbitrary finite P exactly). `points` is a *sequence*, not a set:
/// duplicate points yield duplicate unit spans, so `|Σ|` equals the number of
/// points yielded — still a cover; dedup first if S7's set-cardinality
/// reading matters. Not `inc(t, 0)`: that advances `sig(t)` and over-captures
/// past a trailing-zero point's subtree. Total over a mixed-length P
/// (per-point spans are never merged, so no level gate) — but a mixed-length
/// output is un-normalizable by design (S8's gate fires on `normalize`). Not
/// normalized — normalizing could coalesce and break `|Σ| = |P|`; the caller
/// normalizes for a minimal form (one-length P only). An empty P covers `⟨⟩`.
///
/// P is any walk over borrowed points, read once — the same shape [`hull`]
/// takes, so the two S0/S7 point-set operations accept one caller's iterator
/// alike.
pub fn cover<'p>(points: impl IntoIterator<Item = &'p Tumbler>) -> SpanSet {
    points.into_iter().map(subtree_of).collect()
}
