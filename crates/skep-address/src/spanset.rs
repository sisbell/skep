//! §G — span-sets: the union-denoting collection, canonical normalization,
//! and the set-level algebra (ASN-0053: S0, S7–S11, N1/N2). The algebra is
//! interval arithmetic over a hierarchical ordered space — not finite-set
//! manipulation, not byte counting: every span denotes an infinite set
//! (deeper sub-extensions fill every interval), which is why no span-set
//! denotes an arbitrary finite point set exactly (S7's binding fact).

use serde::{Deserialize, Serialize};

use crate::arith::shift;
use crate::error::LevelMismatch;
use crate::span::{subtree_of, Span};
use crate::tumbler::{Nat, Tumbler};

/// An unordered union-denoting collection of spans (`⟦Σ⟧ = ⋃ ⟦σᵢ⟧`).
///
/// Raw `PartialEq`/`Eq`/`Hash` are **STRUCTURAL** — they distinguish
/// un-normalized forms and are NOT denotational identity. The denotational,
/// content-addressed identity is [`CanonicalForm`] (S9); use that as a
/// dedup/cache key, never a raw `SpanSet`.
///
/// Backing (design default): `im::Vector<Span>` — structural sharing makes
/// each derived span-set a new value cheaply sharing the old, exactly the
/// cheap-versioned-immutable-value shape wanted here (this is where `im`
/// earns its keep, not on the tumbler). Serde: both sides derived — raw
/// `SpanSet` carries no standing invariant (un-normalized is legal), and the
/// members serialize and validate through `Span`'s own symmetric shadows, so
/// the round-trip guarantee is inherited.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpanSet(im::Vector<Span>);

/// The unique normalized form (S9) as a content-addressed identity: `Hash +
/// Eq`, so it serves directly as M7's IN-MEMORY dedup/cache key (M7 hashes it
/// into an opaque `LockKey`; a hash collision is harmless because the dedup
/// *decision* compares by `Eq`, not by the lock tag).
///
/// DELIBERATELY not `Serialize`/`Deserialize` (the documented default): the
/// dedup key lives in memory and is rebuilt by replay, never journaled. If M7
/// ever journals or checkpoints it, add a symmetric `into`/`try_from =
/// "SpanSet"` shadow pair whose deserialize side re-establishes
/// `is_normalized` — the same no-unguarded-mint rule as
/// `Tumbler`/`Address`/`Span`.
///
/// Invariant: the inner `SpanSet` is normalized (construction is gated on
/// [`canonical_key`]; no mutable access exists).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalForm(SpanSet);

impl CanonicalForm {
    /// Read-only view of the normalized inner set — the invariant is
    /// preserved. This is the seam accessor M7's coverage-class policy
    /// composes per-class canonical forms through, and what a collision-free
    /// `LockKey` or a future serialization would read.
    pub fn as_set(&self) -> &SpanSet {
        &self.0
    }
}

impl SpanSet {
    /// `⟨⟩ ≜ ∅` — the empty designation, structurally distinct from any
    /// zero-width span (which the span constructor rejects, T12/S2).
    pub fn empty() -> SpanSet {
        SpanSet(im::Vector::new())
    }

    pub fn singleton(s: Span) -> SpanSet {
        SpanSet(im::Vector::unit(s))
    }

    /// `|Σ|` — the component-span count.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `len() == 0 ⟺ ⟨⟩`.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Component spans in STORED order (N1 ascending starts iff normalized;
    /// insertion order otherwise) — a structural view, like the raw
    /// `Eq`/`Hash`. This is the read surface downstream consumers walk: M7's
    /// per-slot spanfilade build, M8's RETRIEVEENDSETS/projection, M6/M10
    /// result marshaling, and `difference`'s ≤ 2-span result.
    pub fn iter(&self) -> impl Iterator<Item = &Span> {
        self.0.iter()
    }

    /// S8/S9 — the unique canonical form (N1 ∧ N2): sort by start, then one
    /// linear sweep coalescing every overlapping or adjacent pair
    /// (`reachᵢ ≥ startᵢ₊₁`); O(n log n), dominated by the sort. Gate — the
    /// FULL S8 precondition: every component span level-uniform
    /// (`#start = #width`, without which the coalescing start↔reach
    /// arithmetic breaks) AND all components mutually level-compatible
    /// (starts of one length), else `Err(LevelMismatch)`. Pinned edge:
    /// `normalize(⟨⟩) = Ok(⟨⟩)` — S8's n = 0 case, vacuously N1 ∧ N2.
    pub fn normalize(&self) -> Result<SpanSet, LevelMismatch> {
        let Some(class) = self.length_class() else {
            return Ok(SpanSet::empty());
        };
        for s in self.0.iter() {
            if !s.is_level_uniform() || s.start().len() != class {
                return Err(LevelMismatch);
            }
        }
        let mut endpoints: Vec<(Tumbler, Tumbler)> = self
            .0
            .iter()
            .map(|s| (s.start().clone(), s.reach()))
            .collect();
        endpoints.sort_by(|x, y| x.0.cmp(&y.0));
        let mut out: Vec<Span> = Vec::new();
        let mut rest = endpoints.into_iter();
        let (mut cur_start, mut cur_reach) = rest.next().expect("nonempty: length_class was Some");
        for (s, r) in rest {
            if s <= cur_reach {
                // overlap or adjacency — coalesce (N2)
                if r > cur_reach {
                    cur_reach = r;
                }
            } else {
                out.push(
                    Span::from_endpoints(cur_start, cur_reach)
                        .expect("gated one-length endpoints with start < reach"),
                );
                cur_start = s;
                cur_reach = r;
            }
        }
        out.push(
            Span::from_endpoints(cur_start, cur_reach)
                .expect("gated one-length endpoints with start < reach"),
        );
        Ok(out.into_iter().collect())
    }

    /// True iff this set already IS its canonical form. `true` for ⟨⟩
    /// (vacuous N1 ∧ N2); a set outside S8's domain (level-mismatched) has no
    /// canonical form and answers `false`.
    pub fn is_normalized(&self) -> bool {
        match self.normalize() {
            Ok(n) => n == *self,
            Err(LevelMismatch) => false,
        }
    }

    /// ⟦Σ⟧ membership: some component span contains `t`; ⟨⟩ denotes nothing.
    pub fn denotes(&self, t: &Tumbler) -> bool {
        self.0.iter().any(|s| s.contains(t))
    }

    /// The start-length of the first component — `None` for ⟨⟩. Meaningful
    /// as *the* single length class only under the level gate.
    fn length_class(&self) -> Option<usize> {
        self.0.front().map(|s| s.start().len())
    }
}

/// The general constructor: collect AS GIVEN — no normalization, no level
/// gate, no singleton+union folding; the caller normalizes.
impl FromIterator<Span> for SpanSet {
    fn from_iter<I: IntoIterator<Item = Span>>(iter: I) -> SpanSet {
        SpanSet(iter.into_iter().collect())
    }
}

/// S10 — the ⊕-free join: CONCATENATION ONLY — never normalizes, never fails
/// (total). Commutative and associative up to the canonical form, with
/// idempotence following as a derived corollary, so span-sets form a
/// join-semilattice within one tumbler length: workers accumulate and merge
/// in any order to a deterministic canonical result, coordination-free.
/// Normalization is the caller's separate (eager or lazy) step — the merge
/// path stays union-only because difference is not order-free.
pub fn union(a: &SpanSet, b: &SpanSet) -> SpanSet {
    let mut joined = a.0.clone();
    joined.append(b.0.clone());
    SpanSet(joined)
}

/// Set intersection as one sweep-line pass over the two canonical forms.
/// Normalizes BOTH inputs internally — so the error is honest:
/// `LevelMismatch` fires when a set is not internally level-uniform *or* the
/// two sets are not mutually level-compatible — and emits a normalized
/// result.
pub fn intersect_sets(a: &SpanSet, b: &SpanSet) -> Result<SpanSet, LevelMismatch> {
    let na = a.normalize()?;
    let nb = b.normalize()?;
    let (Some(la), Some(lb)) = (na.length_class(), nb.length_class()) else {
        return Ok(SpanSet::empty()); // ⟨⟩ on either side
    };
    if la != lb {
        return Err(LevelMismatch);
    }
    let av: Vec<(Tumbler, Tumbler)> = na.iter().map(|s| (s.start().clone(), s.reach())).collect();
    let bv: Vec<(Tumbler, Tumbler)> = nb.iter().map(|s| (s.start().clone(), s.reach())).collect();
    let (mut i, mut j) = (0usize, 0usize);
    let mut out: Vec<Span> = Vec::new();
    while i < av.len() && j < bv.len() {
        let lo = std::cmp::max(&av[i].0, &bv[j].0);
        let hi = std::cmp::min(&av[i].1, &bv[j].1);
        if lo < hi {
            out.push(
                Span::from_endpoints(lo.clone(), hi.clone())
                    .expect("one length class with lo < hi"),
            );
        }
        if av[i].1 <= bv[j].1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    Ok(out.into_iter().collect())
}

/// Set difference `⟦a⟧ \ ⟦b⟧` as one sweep over the two canonical forms.
/// Normalizes both inputs internally; emits a normalized result. NO proven
/// output-size bound (open, per the design) — the result is not
/// size-promised.
pub fn difference_sets(a: &SpanSet, b: &SpanSet) -> Result<SpanSet, LevelMismatch> {
    let na = a.normalize()?;
    let nb = b.normalize()?;
    let (Some(la), Some(lb)) = (na.length_class(), nb.length_class()) else {
        // ⟨⟩ \ b = ⟨⟩ ;  a \ ⟨⟩ = a (already normalized)
        return Ok(if na.is_empty() { SpanSet::empty() } else { na });
    };
    if la != lb {
        return Err(LevelMismatch);
    }
    let av: Vec<(Tumbler, Tumbler)> = na.iter().map(|s| (s.start().clone(), s.reach())).collect();
    let bv: Vec<(Tumbler, Tumbler)> = nb.iter().map(|s| (s.start().clone(), s.reach())).collect();
    let mut out: Vec<Span> = Vec::new();
    let mut j = 0usize;
    for (s, r) in av {
        // b-spans wholly at-or-before this a-start can touch no later a-span
        // either (starts ascend), so this cursor advances for good.
        while j < bv.len() && bv[j].1 <= s {
            j += 1;
        }
        let mut cur = s;
        let mut k = j;
        while k < bv.len() && bv[k].0 < r {
            if bv[k].0 > cur {
                out.push(
                    Span::from_endpoints(cur.clone(), bv[k].0.clone())
                        .expect("one length class with cur < b-start"),
                );
            }
            if bv[k].1 > cur {
                cur = bv[k].1.clone();
            }
            if cur >= r {
                break;
            }
            k += 1;
        }
        if cur < r {
            out.push(Span::from_endpoints(cur, r).expect("one length class with cur < reach"));
        }
    }
    Ok(out.into_iter().collect())
}

/// S9 — the equality oracle: normalize both, compare. Inherits `normalize`'s
/// *per-set* fallibility; two internally-uniform sets in DIFFERENT length
/// classes normalize independently and compare unequal — `Ok(false)`, NOT an
/// error (§7; denotationally sound: equal non-empty denotations share a
/// minimum element, forcing a single length class).
pub fn equiv(a: &SpanSet, b: &SpanSet) -> Result<bool, LevelMismatch> {
    Ok(a.normalize()? == b.normalize()?)
}

/// S9 — the unique normalized form wrapped as the denotational dedup/cache
/// key: the seam M7's link-dedup coverage-class policy rides (M1 computes the
/// canonical form; M7 decides the class *policy* and supplies the key to
/// M2's keyed critical section — M2 never computes it). `canonical_key(⟨⟩)`
/// succeeds with the empty canonical form. A heterogeneous-length endset
/// falls outside S8/S9 and yields `LevelMismatch` — cross-length denotational
/// canonicalization is genuinely absent from the source algebra, so M7
/// partitions by endpoint length and composes per-class keys (read back
/// through [`CanonicalForm::as_set`]).
pub fn canonical_key(s: &SpanSet) -> Result<CanonicalForm, LevelMismatch> {
    Ok(CanonicalForm(s.normalize()?))
}

/// S0 — the single-span convex hull of a finite point set. The only real
/// precondition is `#min P = #max P` (by convexity the hull then covers even
/// a MIXED-length P): `None` if P is empty or `#min ≠ #max` (WF cannot
/// fire); else `from_endpoints(min P, shift(max P, 1))`. The reach is
/// `shift(max, 1)` — the LEAST same-length tumbler exceeding max (TS4,
/// length-preserving) — so the hull is TIGHT and the name honest;
/// `inc(max, 0)` would also cover ⊇ P but over-captures whenever
/// `sig(max) < #max`. One reach convention — `shift(·, 1)` — serves
/// [`subtree_of`], [`cover`], and `hull` alike. The `|Σ| = |P|` unit-span
/// cover for arbitrary P (S7) is the separate [`cover`], not this hull.
pub fn hull(points: &[Tumbler]) -> Option<Span> {
    let lo = points.iter().min()?;
    let hi = points.iter().max()?;
    if lo.len() != hi.len() {
        return None;
    }
    let reach = shift(hi, &Nat::from(1u32));
    Some(
        Span::from_endpoints(lo.clone(), reach)
            .expect("min ≤ max < shift(max,1) at one shared length, so WF fires"),
    )
}

/// S7 — the unit-span cover of a finite point set: one unit span per point
/// with S7's exact witness width `δ(1, #t)` — i.e. each unit span IS
/// `subtree_of(t)`, so `cover` and `subtree_of` share one construction —
/// `union`-joined (concatenation). `|Σ| = |P|` and `⟦Σ⟧ ⊇ P` — a COVER, not
/// exact (S7's binding fact: no span-set denotes an arbitrary finite P
/// exactly). `points` is a SLICE, not a set: duplicate points yield duplicate
/// unit spans, so `|Σ|` equals the slice length — still a cover; dedup first
/// if S7's set-cardinality reading matters. NOT `inc(t, 0)`: that advances
/// `sig(t)` and over-captures past a trailing-zero point's subtree. Total
/// over a MIXED-length P (per-point spans are never merged, so no level
/// gate) — but a mixed-length output is un-normalizable BY DESIGN (S8's gate
/// fires on `normalize`). NOT normalized — normalizing could coalesce and
/// break `|Σ| = |P|`; the caller normalizes for a minimal form (one-length P
/// only). `cover(&[]) = ⟨⟩`.
pub fn cover(points: &[Tumbler]) -> SpanSet {
    points.iter().map(subtree_of).collect()
}
