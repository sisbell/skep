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

use crate::arith::{action_point, add, shift, sub};
use crate::error::LevelMismatch;
use crate::spanset::SpanSet;
use crate::tumbler::{Nat, Tumbler};

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
    /// T12: `width > 0 ∧ actionPoint(width) ≤ #start` — both required for
    /// `reach > start`.
    pub fn new(start: Tumbler, width: Tumbler) -> Result<Span, T12Clause> {
        match action_point(&width) {
            None => Err(T12Clause::ZeroWidth),
            Some(k) if k > start.len() => Err(T12Clause::ActionPointTooDeep),
            Some(_) => Ok(Span { start, width }),
        }
    }

    /// WF: `s < r ∧ #s = #r ⇒ (s, r ⊖ s)`. The level clause `#s = #r` is
    /// checked FIRST (gate-first, design §6): a pair failing both yields
    /// `LevelMismatch`, not `NotIncreasing`.
    pub fn from_endpoints(s: Tumbler, r: Tumbler) -> Result<Span, WfError> {
        if s.len() != r.len() {
            return Err(WfError::LevelMismatch);
        }
        if s >= r {
            return Err(WfError::NotIncreasing);
        }
        let width = sub(&r, &s).expect("s < r ⇒ r ≥ s");
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

/// T5 subtree-capture: the span denoting exactly prefix `p`'s subtree — every
/// extension of `p` — for ANY carrier prefix, trailing zero included.
/// Warranted by T5's contiguity (ASN-0034: a prefix's subtree is a contiguous
/// T1 interval), with the width `δ(1, #p)` reusing S7's covering-construction
/// witness (ASN-0053). The width advances position `#p`, NOT `sig(p)`: using
/// `inc(p, 0)` would over-capture on a trailing-zero prefix (e.g.
/// `inc([2,0],0) = [3,0]` admits `[2,1]`, which is not an extension of
/// `[2,0]`). Total — `shift(p,1) > p` (TS4) and length-preserving, so WF
/// always fires; returns `Span`, not `Result`.
pub fn subtree_of(p: &Tumbler) -> Span {
    let reach = shift(p, &Nat::from(1u32));
    Span::from_endpoints(p.clone(), reach)
        .expect("TS4: shift(p,1) > p at the same length, so WF fires")
}

/// SC's five mutually-exclusive cases, decided by pure endpoint comparison.
///
/// NOTE (design/interface conflict, resolved in the interface's favor): the
/// design encodes orientation in the variants (`ProperOverlap {
/// first_starts_first }`, `Containment { first_contains_second }`) so S11d
/// consumers need not re-compare endpoints; the interface — the verbatim
/// binding for dependents — declares bare unit variants, implemented here
/// exactly. [`difference`] recovers orientation internally by endpoint
/// comparison; M6/M8 consumers needing direction must do the same until the
/// documents reconcile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// SC — pure order, **no level gate** (the classifier constructs nothing);
/// total on any spans, sentinel endpoints and mixed lengths included. The
/// five boundary predicates are spelled once, here, checked in this order:
/// separated, adjacent, equal, containment, proper overlap.
pub fn classify_spans(a: &Span, b: &Span) -> SpanRel {
    let (ra, rb) = (a.reach(), b.reach());
    let max_start = max(a.start(), b.start());
    let min_reach = min(&ra, &rb);
    if max_start > min_reach {
        return SpanRel::Separated;
    }
    if max_start == min_reach {
        return SpanRel::Adjacent;
    }
    if a.start() == b.start() && ra == rb {
        return SpanRel::Equal;
    }
    let a_brackets_b = a.start() <= b.start() && rb <= ra;
    let b_brackets_a = b.start() <= a.start() && ra <= rb;
    if a_brackets_b || b_brackets_a {
        return SpanRel::Containment;
    }
    SpanRel::ProperOverlap
}

/// S6 level gate — per-span level-uniformity ∧ mutual compatibility (every
/// endpoint shares one length L). Runs UNCONDITIONALLY at entry on the four
/// fallible pairwise ops, **before branch dispatch**: mismatched-level
/// operands yield `Err(LevelMismatch)` even on non-constructing branches
/// (Separated operands never yield `Ok(None)`/`Ok({a})`). Only
/// [`classify_spans`] is gate-free.
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
    let (ra, rb) = (a.reach(), b.reach());
    let lo = max(a.start(), b.start());
    let hi = min(&ra, &rb);
    if lo < hi {
        Ok(Some(
            Span::from_endpoints(lo.clone(), hi.clone())
                .expect("gated one-length endpoints with lo < hi"),
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
    let (ra, rb) = (a.reach(), b.reach());
    if max(a.start(), b.start()) > min(&ra, &rb) {
        return Ok(None); // separated
    }
    let lo = min(a.start(), b.start()).clone();
    let hi = max(&ra, &rb).clone();
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
    let left = Span::from_endpoints(s.start().clone(), p.clone())
        .expect("gated one-length endpoints with start < p");
    let right =
        Span::from_endpoints(p.clone(), reach).expect("gated one-length endpoints with p < reach");
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
    let (ra, rb) = (a.reach(), b.reach());
    match classify_spans(a, b) {
        SpanRel::Separated | SpanRel::Adjacent => Ok(SpanSet::singleton(a.clone())),
        SpanRel::Equal => Ok(SpanSet::empty()),
        SpanRel::Containment => {
            if a.start() <= b.start() && rb <= ra {
                // a ⊃ b (Equal already excluded)
                let mut parts: Vec<Span> = Vec::with_capacity(2);
                if a.start() < b.start() {
                    parts.push(
                        Span::from_endpoints(a.start().clone(), b.start().clone())
                            .expect("gated one-length endpoints with start a < start b"),
                    );
                }
                if rb < ra {
                    parts.push(
                        Span::from_endpoints(rb, ra)
                            .expect("gated one-length endpoints with reach b < reach a"),
                    );
                }
                Ok(parts.into_iter().collect())
            } else {
                // a ⊂ b: nothing of a survives
                Ok(SpanSet::empty())
            }
        }
        SpanRel::ProperOverlap => {
            let part = if a.start() < b.start() {
                Span::from_endpoints(a.start().clone(), b.start().clone())
                    .expect("gated one-length endpoints with start a < start b")
            } else {
                Span::from_endpoints(rb, ra)
                    .expect("gated one-length endpoints with reach b < reach a")
            };
            Ok(SpanSet::singleton(part))
        }
    }
}
