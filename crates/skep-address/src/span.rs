//! §F — spans: T12 values, WF construction, SC classification, and the
//! pairwise interval algebra (ASN-0053: WF/SC/S1–S6/S11; ASN-0034: T5, TA6).
//!
//! The whole single-span engine is one comparator, one constructor
//! (WF/`from_endpoints`), and min/max under the order — not four
//! independently-reasoned operations (design §6).

use std::cmp::{max, min};
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::arith::{add, add_domain, next_at_length, sub, AddDomain};
use crate::error::LevelMismatch;
use crate::spanset::SpanSet;
use crate::tumbler::Tumbler;

/// [`Span::new`] rejection — the violated T12 clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T12Clause {
    /// `¬Pos(width)`. A zero-width span is an illegal state the constructor
    /// must reject, never the representation of "nothing" — the empty
    /// designation is `SpanSet::empty()` (⟨⟩).
    ZeroWidth,
    /// `actionPoint(width) > #start`.
    ActionPointTooDeep,
}

impl fmt::Display for T12Clause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            T12Clause::ZeroWidth => "T12: span width is the zero displacement",
            T12Clause::ActionPointTooDeep => "T12: width's action point exceeds #start",
        })
    }
}
impl Error for T12Clause {}

/// [`Span::from_endpoints`] rejection (WF: `s < r ∧ #s = #r`). The level
/// clause is checked FIRST (gate-first, design §6): a pair failing both
/// yields `LevelMismatch`, not `NotIncreasing`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WfError {
    /// `¬(s < r)` — endpoints not strictly increasing.
    NotIncreasing,
    /// `#s ≠ #r` — endpoints in different length classes.
    LevelMismatch,
}

impl fmt::Display for WfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            WfError::NotIncreasing => "WF failed: endpoints not strictly increasing (s < r)",
            WfError::LevelMismatch => "WF failed: endpoint lengths differ (#s ≠ #r)",
        })
    }
}
impl Error for WfError {}

/// A half-open interval of the tumbler order: `(start, width)` authoritative
/// — the spec's form, aligning the edit primitive with the storage primitive
/// — with `reach = start ⊕ width` a derived recomputation of immutable
/// inputs, never persisted as authoritative state.
///
/// Endpoints are raw carrier tumblers: an all-zero tumbler is rejected as an
/// *address* but is a legitimate span endpoint (unbounded lower-bound
/// sentinel, TA6) — the address validator is deliberately not consulted at
/// this boundary.
///
/// Serde: a **symmetric shadow pair** — serializes as the `(start, width)`
/// pair (via `From<Span> for (Tumbler, Tumbler)`) and deserializes through
/// [`Span::new`], re-checking T12 on replay. The symmetry is load-bearing: a
/// plain derived `Serialize` beside the shadowed `Deserialize` could not
/// round-trip its own output under a self-describing format (design
/// preamble).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "(Tumbler, Tumbler)", try_from = "(Tumbler, Tumbler)")]
pub struct Span {
    start: Tumbler,
    width: Tumbler,
}

/// Serialization shadow: the authoritative `(start, width)` pair.
impl From<Span> for (Tumbler, Tumbler) {
    fn from(s: Span) -> (Tumbler, Tumbler) {
        (s.start, s.width)
    }
}

/// Deserialization mint path: routes through [`Span::new`] (T12) — no journal
/// replay can smuggle in a zero-width span.
impl TryFrom<(Tumbler, Tumbler)> for Span {
    type Error = T12Clause;
    fn try_from((start, width): (Tumbler, Tumbler)) -> Result<Span, T12Clause> {
        Span::new(start, width)
    }
}

impl Span {
    /// T12: `width > 0 ∧ actionPoint(width) ≤ #start`. T12 IS `⊕`'s domain,
    /// asked of `⊕` itself rather than restated here — which is what makes
    /// [`Span::reach`] total, since the pair a `Span` holds is by
    /// construction a pair `⊕` accepts.
    pub fn new(start: Tumbler, width: Tumbler) -> Result<Span, T12Clause> {
        match add_domain(&start, &width) {
            Ok(_) => Ok(Span { start, width }),
            Err(AddDomain::ZeroDisplacement) => Err(T12Clause::ZeroWidth),
            Err(AddDomain::ActionPointTooDeep) => Err(T12Clause::ActionPointTooDeep),
        }
    }

    /// WF: `s < r ∧ #s = #r ⇒ (s, r ⊖ s)`. The level clause `#s = #r` is
    /// checked FIRST (gate-first, design §6): a pair failing both yields
    /// `LevelMismatch`, not `NotIncreasing`.
    ///
    /// The asymmetry in the signature is the arithmetic: `s` is kept as the
    /// span's start, `r` is only measured against it and never stored, so the
    /// reach is borrowed and a caller holding one need not copy it to be read.
    pub fn from_endpoints(s: Tumbler, r: &Tumbler) -> Result<Span, WfError> {
        if s.len() != r.len() {
            return Err(WfError::LevelMismatch);
        }
        if s >= *r {
            return Err(WfError::NotIncreasing);
        }
        let width = sub(r, &s).expect("s < r ⇒ r ≥ s");
        Ok(Span::new(s, width).expect("same-length s < r yields a T12-valid width"))
    }

    /// The lower endpoint (inclusive).
    pub fn start(&self) -> &Tumbler {
        &self.start
    }

    /// The authoritative displacement.
    pub fn width(&self) -> &Tumbler {
        &self.width
    }

    /// `start ⊕ width` — recomputed on demand (a derivation of immutable
    /// inputs, never desynchronizable, never persisted as authoritative).
    /// Total: T12 is exactly ⊕'s precondition here.
    pub fn reach(&self) -> Tumbler {
        add(&self.start, &self.width).expect("T12 ⇒ ⊕ precondition holds")
    }

    /// Membership: `start ≤ t < reach` — two comparisons, half-open.
    pub fn contains(&self, t: &Tumbler) -> bool {
        *t >= self.start && *t < self.reach()
    }

    /// S6: `#start = #width` — the per-span half of the level gate.
    pub fn is_level_uniform(&self) -> bool {
        self.start.len() == self.width.len()
    }
}

/// A span in its DERIVED `(start, reach)` form — the working shape of a
/// sweep, where every comparison is between endpoints rather than between a
/// start and a displacement, and the reach is worth computing once at the
/// head instead of at each step.
///
/// It carries a name because `(start, width)` is the authoritative form and
/// the two pairs are not interchangeable: read as a width, a reach denotes a
/// different span entirely, and an anonymous pair of tumblers says which of
/// the two it is nowhere. The name is the constructor's — a pair of endpoints
/// is what [`Span::from_endpoints`] takes — and the way back to the
/// authoritative form is [`Endpoints::into_span`], which IS that conversion,
/// so WF travels with it.
#[derive(Debug, Clone)]
pub(crate) struct Endpoints {
    pub(crate) start: Tumbler,
    pub(crate) reach: Tumbler,
}

impl Endpoints {
    /// The derived form of `s` — one `reach()` recomputation.
    pub(crate) fn of(s: &Span) -> Endpoints {
        Endpoints {
            start: s.start().clone(),
            reach: s.reach(),
        }
    }

    /// A pair of endpoints a sweep computed, still to be checked by WF.
    pub(crate) fn new(start: Tumbler, reach: Tumbler) -> Endpoints {
        Endpoints { start, reach }
    }

    /// Back to the authoritative `(start, width)` form (WF).
    pub(crate) fn into_span(self) -> Result<Span, WfError> {
        let Endpoints { start, reach } = self;
        Span::from_endpoints(start, &reach)
    }
}

/// T5 subtree-capture: the span denoting exactly prefix `p`'s subtree — every
/// extension of `p` — for ANY carrier prefix, trailing zero included.
/// Warranted by T5's contiguity (ASN-0034: a prefix's subtree is a contiguous
/// T1 interval), with the width `δ(1, #p)` reusing S7's covering-construction
/// witness (ASN-0053). The width advances position `#p`, NOT `sig(p)`: using
/// `inc(p, 0)` would over-capture on a trailing-zero prefix (e.g.
/// `inc([2,0],0) = [3,0]` admits `[2,1]`, which is not an extension of
/// `[2,0]`). Total — the reach is `next_at_length(p)`, strictly greater (TS4)
/// and length-preserving, so WF always fires; returns `Span`, not `Result`.
pub fn subtree_of(p: &Tumbler) -> Span {
    Span::from_endpoints(p.clone(), &next_at_length(p))
        .expect("TS4: next_at_length(p) > p at the same length, so WF fires")
}

/// SC's five mutually-exclusive cases, decided by pure endpoint comparison.
///
/// NOTE (design/interface conflict, resolved in the interface's favor): the
/// design encodes orientation in the variants (`ProperOverlap {
/// first_starts_first }`, `Containment { first_contains_second }`) so S11d
/// consumers need not re-compare endpoints; the interface — the verbatim
/// binding for dependents — declares bare unit variants, implemented here
/// exactly. Orientation survives inside M1, where [`difference`] reads it off
/// the oriented classification these five cases project from; an M6/M8
/// consumer needing direction must re-compare endpoints until the documents
/// reconcile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpanRel {
    /// max start > min reach — no shared position.
    Separated,
    /// max start = min reach — touching; half-open ⇒ still no shared position.
    Adjacent,
    /// Each span extends past the other on exactly one side.
    ProperOverlap,
    /// One span's endpoints bracket the other's, and the spans are not equal.
    Containment,
    /// Both endpoint pairs coincide.
    Equal,
}

/// SC with the orientation kept: which operand contains which, and which
/// starts first. [`SpanRel`] is this with the orientation dropped, and
/// [`difference`] — the one operation whose construction depends on it —
/// reads it here rather than re-deriving it from the endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OrientedRel {
    Separated,
    Adjacent,
    Equal,
    /// `a` strictly brackets `b`.
    AContainsB,
    /// `b` strictly brackets `a`.
    BContainsA,
    /// Proper overlap, `a` starting first.
    OverlapAFirst,
    /// Proper overlap, `b` starting first.
    OverlapBFirst,
}

/// The one site that decides the five-case classification — pure order, no
/// level gate (it constructs nothing), total on any pair, sentinel endpoints
/// and mixed lengths included. Checked in this order: separated, adjacent,
/// equal, containment, proper overlap. Past Equal and containment the starts
/// must differ, so the overlap orientation is the one remaining comparison.
///
/// Takes [`Endpoints`] rather than spans: every predicate below is an endpoint
/// comparison, so the two reaches are derived once by the caller instead of
/// once per question. [`intersect`] and [`merge`] each decide a single
/// boundary question inline rather than classifying — a deliberate cheap
/// path, and the reason this is not the only place a boundary is compared.
fn relate(a: &Endpoints, b: &Endpoints) -> OrientedRel {
    let max_start = max(&a.start, &b.start);
    let min_reach = min(&a.reach, &b.reach);
    if max_start > min_reach {
        return OrientedRel::Separated;
    }
    if max_start == min_reach {
        return OrientedRel::Adjacent;
    }
    if a.start == b.start && a.reach == b.reach {
        return OrientedRel::Equal;
    }
    if a.start <= b.start && b.reach <= a.reach {
        return OrientedRel::AContainsB;
    }
    if b.start <= a.start && a.reach <= b.reach {
        return OrientedRel::BContainsA;
    }
    if a.start < b.start {
        OrientedRel::OverlapAFirst
    } else {
        OrientedRel::OverlapBFirst
    }
}

/// SC — pure order, **no level gate**; total on any spans, sentinel endpoints
/// and mixed lengths included. The projection of the oriented `relate` onto
/// the five bare cases the interface declares.
pub fn classify_spans(a: &Span, b: &Span) -> SpanRel {
    match relate(&Endpoints::of(a), &Endpoints::of(b)) {
        OrientedRel::Separated => SpanRel::Separated,
        OrientedRel::Adjacent => SpanRel::Adjacent,
        OrientedRel::Equal => SpanRel::Equal,
        OrientedRel::AContainsB | OrientedRel::BContainsA => SpanRel::Containment,
        OrientedRel::OverlapAFirst | OrientedRel::OverlapBFirst => SpanRel::ProperOverlap,
    }
}

/// S6 level gate — per-span level-uniformity ∧ mutual compatibility (every
/// endpoint shares one length L). Runs UNCONDITIONALLY at entry on the four
/// fallible pairwise ops, **before branch dispatch**: mismatched-level
/// operands yield `Err(LevelMismatch)` even on non-constructing branches
/// (Separated operands never yield `Ok(None)`/`Ok({a})`). Only
/// [`classify_spans`] is gate-free.
///
/// One rule at two scales: this is the pairwise instance of
/// [`SpanSet::level_class`], which asks the same question of a whole
/// collection and answers with the shared length itself.
fn level_gate(a: &Span, b: &Span) -> Result<(), LevelMismatch> {
    if a.is_level_uniform() && b.is_level_uniform() && a.start().len() == b.start().len() {
        Ok(())
    } else {
        Err(LevelMismatch)
    }
}

/// S11a — `(max start, min reach)` after the gate; ≤ 1 span (S1).
/// Self-guarding on disjointness: disjoint or adjacent operands give
/// `max start ≥ min reach`, failing WF's `s < r`, correctly yielding
/// `Ok(None)` with no SC call.
pub fn intersect(a: &Span, b: &Span) -> Result<Option<Span>, LevelMismatch> {
    level_gate(a, b)?;
    let (ea, eb) = (Endpoints::of(a), Endpoints::of(b));
    let lo = max(&ea.start, &eb.start);
    let hi = min(&ea.reach, &eb.reach);
    if lo < hi {
        Ok(Some(
            Span::from_endpoints(lo.clone(), hi).expect("gated one-length endpoints with lo < hi"),
        ))
    } else {
        Ok(None)
    }
}

/// S3 — `(min start, max reach)`: exactly 1 span when overlapping or adjacent
/// (S3a), `Ok(None)` when separated. NOT self-guarding, so one comparison
/// decides separation first — cheaper than full SC (only SC is skipped; the
/// gate is not).
pub fn merge(a: &Span, b: &Span) -> Result<Option<Span>, LevelMismatch> {
    level_gate(a, b)?;
    let (ea, eb) = (Endpoints::of(a), Endpoints::of(b));
    if max(&ea.start, &eb.start) > min(&ea.reach, &eb.reach) {
        return Ok(None); // separated
    }
    let lo = min(&ea.start, &eb.start).clone();
    let hi = max(&ea.reach, &eb.reach);
    Ok(Some(
        Span::from_endpoints(lo, hi).expect("non-separated gated operands give lo < hi"),
    ))
}

/// [`split`] rejection. The level conditions run FIRST (gate-first, design
/// §6): `LevelMismatch` wins when both fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitError {
    /// `¬(start < p < reach)` — the point is not strictly interior.
    NotInterior,
    /// σ not level-uniform (S4) or `#start ≠ #p`.
    LevelMismatch,
}

impl fmt::Display for SplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SplitError::NotInterior => "split failed: point not strictly interior (start < p < reach)",
            SplitError::LevelMismatch => "split failed: level conditions violated (S4/S6)",
        })
    }
}
impl Error for SplitError {}

/// S4 — split σ at an interior point. Requires σ itself level-uniform (S4 —
/// so `reach ⊖ p` shares the common length) AND `#start = #p` AND
/// `start < p < reach` (strictly interior: a boundary `p` would mint a
/// forbidden zero-width part, S2), **checked in that order** (gate-first:
/// both level conditions before interiority, so an input failing both yields
/// `LevelMismatch`, not `NotInterior`). Returns `(start, p ⊖ start)` and
/// `(p, reach ⊖ p)` — adjacent by construction, widths composing to the
/// whole (S5).
pub fn split(s: &Span, p: &Tumbler) -> Result<(Span, Span), SplitError> {
    if !s.is_level_uniform() || s.start().len() != p.len() {
        return Err(SplitError::LevelMismatch);
    }
    let reach = s.reach();
    if !(s.start() < p && *p < reach) {
        return Err(SplitError::NotInterior);
    }
    let left = Span::from_endpoints(s.start().clone(), p)
        .expect("gated one-length endpoints with start < p");
    let right =
        Span::from_endpoints(p.clone(), &reach).expect("gated one-length endpoints with p < reach");
    Ok((left, right))
}

/// S11d — `⟦a⟧ \ ⟦b⟧` as ≤ 2 spans; the only op needing full SC:
///
/// | SC case | `⟦a⟧ \ ⟦b⟧` | spans |
/// |---|---|---|
/// | Separated / Adjacent | `⟦a⟧` | 1 |
/// | ProperOverlap, a starts first | left complement `[start a, start b)` | 1 |
/// | ProperOverlap, b starts first | right complement `[reach b, reach a)` | 1 |
/// | Containment, a ⊃ b | left + right complements | 1 or 2 |
/// | Containment, a ⊂ b / Equal | ∅ | 0 |
///
/// A coinciding boundary makes that complement zero-width; it fails WF and is
/// dropped — no algebra result ever carries a zero-width member (S2). The
/// dispatch runs after the unconditional gate; the output is emitted in N1
/// order (left before right) and is normalized by construction (§6).
pub fn difference(a: &Span, b: &Span) -> Result<SpanSet, LevelMismatch> {
    level_gate(a, b)?;
    let (ea, eb) = (Endpoints::of(a), Endpoints::of(b));
    // The left complement `[start a, start b)` and the right complement
    // `[reach b, reach a)` — each built only on an arm that has already
    // established that its endpoints increase.
    let left = || {
        Endpoints::new(ea.start.clone(), eb.start.clone())
            .into_span()
            .expect("gated one-length endpoints with start a < start b")
    };
    let right = || {
        Endpoints::new(eb.reach.clone(), ea.reach.clone())
            .into_span()
            .expect("gated one-length endpoints with reach b < reach a")
    };
    match relate(&ea, &eb) {
        OrientedRel::Separated | OrientedRel::Adjacent => Ok(SpanSet::singleton(a.clone())),
        // a ⊆ b: nothing of a survives.
        OrientedRel::Equal | OrientedRel::BContainsA => Ok(SpanSet::empty()),
        OrientedRel::AContainsB => {
            let mut parts: Vec<Span> = Vec::with_capacity(2);
            if ea.start < eb.start {
                parts.push(left());
            }
            if eb.reach < ea.reach {
                parts.push(right());
            }
            Ok(parts.into_iter().collect())
        }
        OrientedRel::OverlapAFirst => Ok(SpanSet::singleton(left())),
        OrientedRel::OverlapBFirst => Ok(SpanSet::singleton(right())),
    }
}
