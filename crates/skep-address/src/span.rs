//! Spans and the pairwise interval algebra over them (§F).
//!
//! The module holds T12 values, WF construction, SC classification, and the
//! pairwise algebra (ASN-0053: WF/SC/S1–S6/S11; ASN-0034: T5, TA6).
//!
//! The whole single-span engine is one comparator, one constructor
//! (WF/`from_endpoints`), and min/max under the order — not four
//! independently-reasoned operations (design §6).

use std::cmp::{max, min};
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::arithmetic::{add, add_domain, next_at_length, sub, AddDomainClause};
use crate::error::LevelMismatch;
use crate::spanset::SpanSet;
use crate::tumbler::Tumbler;

/// [`Span::new`] rejection — the violated T12 clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum T12Clause {
    /// `¬Pos(width)`: the width is the zero displacement.
    ///
    /// A zero-width span is an illegal state the constructor must reject,
    /// never the representation of "nothing" — the empty designation is
    /// `SpanSet::empty()` (⟨⟩).
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

/// The [`Span::from_endpoints`] rejection (WF: `s < r ∧ #s = #r`).
///
/// The level clause is checked *first* (gate-first, design §6): a pair
/// failing both yields `LevelMismatch`, not `NotIncreasing`.
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

/// A half-open interval of the tumbler order, `(start, width)` authoritative.
///
/// `(start, width)` is the spec's form, aligning the edit primitive with the
/// storage primitive; `reach = start ⊕ width` is a derived recomputation of
/// immutable inputs, never persisted as authoritative state.
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

/// The deserialization mint path, routed through [`Span::new`] (T12).
///
/// No journal replay can smuggle in a zero-width span.
///
/// # Errors
///
/// Returns the violated [`T12Clause`] when the pair is not a valid span.
impl TryFrom<(Tumbler, Tumbler)> for Span {
    type Error = T12Clause;
    fn try_from((start, width): (Tumbler, Tumbler)) -> Result<Span, T12Clause> {
        Span::new(start, width)
    }
}

impl Span {
    /// Admits `(start, width)` as a span under T12.
    ///
    /// The clause is `width > 0 ∧ actionPoint(width) ≤ #start`. T12 *is*
    /// `⊕`'s domain, asked of `⊕` itself rather than restated here — which is
    /// what makes [`Span::reach`] total, since the pair a `Span` holds is by
    /// construction a pair `⊕` accepts.
    ///
    /// It consumes both tumblers, like every other admission door here: on the
    /// refusal path they are dropped and [`T12Clause`] carries only the
    /// violated clause — clone before calling if you need the rejected pair
    /// back, the same convention [`crate::validate`] and [`crate::elem_addr`]
    /// state.
    ///
    /// # Errors
    ///
    /// Returns [`T12Clause::ZeroWidth`] when `width` is the zero displacement,
    /// and [`T12Clause::ActionPointTooDeep`] when its action point exceeds
    /// `#start`.
    pub fn new(start: Tumbler, width: Tumbler) -> Result<Span, T12Clause> {
        match add_domain(&start, &width) {
            Ok(_) => Ok(Span { start, width }),
            Err(AddDomainClause::ZeroDisplacement) => Err(T12Clause::ZeroWidth),
            Err(AddDomainClause::ActionPointTooDeep) => Err(T12Clause::ActionPointTooDeep),
        }
    }

    /// Builds the span from endpoints `s` and `r` under WF.
    ///
    /// The rule is `s < r ∧ #s = #r ⇒ (s, r ⊖ s)`. The asymmetry in the
    /// signature is the arithmetic: `s` is kept as the span's start, `r` is
    /// only measured against it and never stored, so the reach is borrowed and
    /// a caller holding one need not copy it to be read.
    ///
    /// # Errors
    ///
    /// The level clause `#s = #r` is checked *first* (gate-first, design §6):
    /// it returns [`WfError::LevelMismatch`] when `#s ≠ #r`, then
    /// [`WfError::NotIncreasing`] when `s ≥ r` — so a pair failing both
    /// yields `LevelMismatch`, not `NotIncreasing`.
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

    /// Returns the lower endpoint (inclusive).
    pub fn start(&self) -> &Tumbler {
        &self.start
    }

    /// Returns the authoritative displacement.
    pub fn width(&self) -> &Tumbler {
        &self.width
    }

    /// Returns `start ⊕ width`, recomputed on demand.
    ///
    /// It is a derivation of immutable inputs, never desynchronizable, never
    /// persisted as authoritative. Total: T12 is exactly ⊕'s precondition
    /// here.
    pub fn reach(&self) -> Tumbler {
        add(&self.start, &self.width).expect("T12 ⇒ ⊕ precondition holds")
    }

    /// Tests membership: `start ≤ t < reach` — two comparisons, half-open.
    pub fn contains(&self, t: &Tumbler) -> bool {
        *t >= self.start && *t < self.reach()
    }

    /// Returns whether the span is level-uniform: S6's `#start = #width`.
    ///
    /// It is the per-span half of the level gate.
    pub fn is_level_uniform(&self) -> bool {
        self.start.len() == self.width.len()
    }
}

/// A span in its derived `(start, reach)` form, the working shape of a sweep.
///
/// In a sweep every comparison is between endpoints rather than between a
/// start and a displacement, and the reach is worth computing once at the
/// head instead of at each step.
///
/// It carries a name because `(start, width)` is the authoritative form and
/// the two pairs are not interchangeable: read as a width, a reach denotes a
/// different span entirely, and an anonymous pair of tumblers says which of
/// the two it is nowhere. The name is the constructor's — a pair of endpoints
/// is what [`Span::from_endpoints`] takes — and the way back to the
/// authoritative form is [`Endpoints::into_span`], which *is* that
/// conversion, so WF travels with it.
#[derive(Debug, Clone)]
pub(crate) struct Endpoints {
    pub(crate) start: Tumbler,
    pub(crate) reach: Tumbler,
}

impl Endpoints {
    /// Returns the derived form of `s` — one `reach()` recomputation.
    pub(crate) fn of(s: &Span) -> Endpoints {
        Endpoints {
            start: s.start().clone(),
            reach: s.reach(),
        }
    }

    /// Converts back to the authoritative `(start, width)` form (WF).
    ///
    /// # Errors
    ///
    /// Returns [`Span::from_endpoints`]'s refusals:
    /// [`WfError::LevelMismatch`] when the endpoints differ in length, then
    /// [`WfError::NotIncreasing`] when `start ≥ reach`.
    pub(crate) fn into_span(self) -> Result<Span, WfError> {
        let Endpoints { start, reach } = self;
        Span::from_endpoints(start, &reach)
    }
}

/// Returns the span denoting exactly `p`'s subtree (T5 subtree-capture).
///
/// The subtree is every extension of `p`, for *any* carrier prefix, trailing
/// zero included. Warranted by T5's contiguity (ASN-0034: a prefix's subtree
/// is a contiguous T1 interval), with the width `δ(1, #p)` reusing S7's
/// covering-construction witness (ASN-0053). The width advances position
/// `#p`, not `sig(p)`: using `inc(p, 0)` would over-capture on a trailing-zero
/// prefix (e.g. `inc([2,0],0) = [3,0]` admits `[2,1]`, which is not an
/// extension of `[2,0]`). Total — the reach is `next_at_length(p)`, strictly
/// greater (TS4) and length-preserving, so WF always fires; returns `Span`,
/// not `Result`.
pub fn subtree_of(p: &Tumbler) -> Span {
    Span::from_endpoints(p.clone(), &next_at_length(p))
        .expect("TS4: next_at_length(p) > p at the same length, so WF fires")
}

/// SC's five mutually-exclusive cases, decided by pure endpoint comparison.
///
/// **Note.** The design and the interface conflict here, and the interface
/// governs: the design encodes orientation in the variants (`ProperOverlap {
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

/// SC with the orientation kept.
///
/// It records which operand contains which, and which starts first.
/// [`SpanRel`] is this with the orientation dropped, and [`difference`] — the
/// one operation whose construction depends on it — reads it here rather than
/// re-deriving it from the endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OrientedRel {
    Separated,
    Adjacent,
    Equal,
    /// `a` brackets `b`, and the two are not equal.
    AContainsB,
    /// `b` brackets `a`, and the two are not equal.
    BContainsA,
    /// Proper overlap, `a` starting first.
    OverlapAFirst,
    /// Proper overlap, `b` starting first.
    OverlapBFirst,
}

/// Decides the five-case classification, the one site that does.
///
/// It is pure order, with no level gate (it constructs nothing), total on any
/// pair, sentinel endpoints and mixed lengths included. Checked in this
/// order: separated, adjacent, equal, containment, proper overlap. Past Equal
/// and containment the starts must differ, so the overlap orientation is the
/// one remaining comparison.
///
/// Takes [`Endpoints`] rather than spans: every predicate below is an endpoint
/// comparison, so the two reaches are derived once by the caller instead of
/// once per question. This is the one site that *classifies*, not the one site
/// a boundary is compared: [`merge`] and the coalescing sweep in
/// [`SpanSet::normalize`] each ask [`separated`] for the single contiguity
/// question they need, and [`intersection`] decides the stricter boundary —
/// three cheap paths past the classifier, each through a named predicate.
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

/// Returns whether the two endpoint pairs neither share a position nor touch.
///
/// The test is `max start > min reach`. Its negation is S3a/N2 contiguity —
/// overlapping or adjacent, hence one interval, hence coalescible — and that
/// is asked at both scales: by [`merge`] for the pairwise join, and by
/// [`SpanSet::normalize`] for the sweep's coalescing step, so the one rule has
/// one spelling.
///
/// `relate` decides the same condition from its own bindings because it needs
/// the three-way split, and [`intersection`]'s boundary is the *stricter* one:
/// adjacency shares no position, so a touching pair is empty for the meet and
/// contiguous for the join.
pub(crate) fn separated(a: &Endpoints, b: &Endpoints) -> bool {
    max(&a.start, &b.start) > min(&a.reach, &b.reach)
}

/// Returns the intersection of two endpoint pairs, as at most one span.
///
/// It is `(max start, min reach)` when that is a WF span, `None` when the
/// operands are disjoint or merely adjacent (S11a's ≤ 1 span). Self-guarding
/// on disjointness: there `max start ≥ min reach`, which fails WF's `s < r`,
/// so no SC call is needed to tell the cases apart.
///
/// # Panics
///
/// Panics if `max start < min reach` but the two differ in length. The
/// caller owes the shared endpoint length — [`gated_endpoints`] establishes
/// it pairwise, and normalization within one length class establishes it for
/// the set-level sweep.
pub(crate) fn intersection(a: &Endpoints, b: &Endpoints) -> Option<Span> {
    let start = max(&a.start, &b.start);
    let reach = min(&a.reach, &b.reach);
    (start < reach).then(|| {
        Span::from_endpoints(start.clone(), reach)
            .expect("level-compatible endpoints with start < reach")
    })
}

/// Returns SC's case for `a` and `b` — pure order, **no level gate**.
///
/// It is total on any spans, sentinel endpoints and mixed lengths included.
/// The projection of the oriented `relate` onto the five bare cases the
/// interface declares.
pub fn classify_spans(a: &Span, b: &Span) -> SpanRel {
    match relate(&Endpoints::of(a), &Endpoints::of(b)) {
        OrientedRel::Separated => SpanRel::Separated,
        OrientedRel::Adjacent => SpanRel::Adjacent,
        OrientedRel::Equal => SpanRel::Equal,
        OrientedRel::AContainsB | OrientedRel::BContainsA => SpanRel::Containment,
        OrientedRel::OverlapAFirst | OrientedRel::OverlapBFirst => SpanRel::ProperOverlap,
    }
}

/// Returns the operands' endpoint pairs, past the S6 level gate.
///
/// The gate and the derived working form come in one step: the two operands'
/// endpoint pairs are obtainable only past the gate — per-span
/// level-uniformity ∧ mutual compatibility (every endpoint shares one length
/// L). It runs unconditionally, **before branch dispatch**, on the three
/// span-pair ops ([`intersect`], [`merge`], [`difference`]): mismatched-level
/// operands yield `Err(LevelMismatch)` even on non-constructing branches
/// (Separated operands never yield `Ok(None)`/`Ok({a})`). [`split`], whose
/// operands are a span and a point rather than two spans, applies the same
/// rule in its own shape and reports it as `SplitError::LevelMismatch`;
/// [`classify_spans`] is gate-free, because it constructs nothing.
///
/// One rule at two scales: this is the pairwise instance of
/// [`SpanSet::level_class`], which asks the same question of a whole
/// collection and answers with the shared length itself.
///
/// # Errors
///
/// Returns [`LevelMismatch`] when either span is not level-uniform or the two
/// starts differ in length.
fn gated_endpoints(a: &Span, b: &Span) -> Result<(Endpoints, Endpoints), LevelMismatch> {
    if a.is_level_uniform() && b.is_level_uniform() && a.start().len() == b.start().len() {
        Ok((Endpoints::of(a), Endpoints::of(b)))
    } else {
        Err(LevelMismatch)
    }
}

/// Returns `⟦a⟧ ∩ ⟦b⟧` as ≤ 1 span (S11a; S1).
///
/// It is `Ok(Some([max start, min reach)))` when the operands share a
/// position, and `Ok(None)` when they are separated or merely **adjacent** —
/// half-open, so a coinciding boundary shares no position and the
/// intersection is empty rather than a point.
///
/// The construction is `intersection`, which the set-level sweep emits through
/// as well, so the intersection of two endpoint pairs is decided in one place.
///
/// # Errors
///
/// Returns [`LevelMismatch`] when the operands fail the level gate. The gate
/// runs unconditionally, before that dispatch, so mismatched-level operands
/// yield `Err` even when they are separated.
pub fn intersect(a: &Span, b: &Span) -> Result<Option<Span>, LevelMismatch> {
    let (ea, eb) = gated_endpoints(a, b)?;
    Ok(intersection(&ea, &eb))
}

/// Merges `a` and `b` into `(min start, max reach)` (S3).
///
/// The result is exactly 1 span when they overlap or are adjacent (S3a), and
/// `Ok(None)` when they are separated. Not self-guarding, so one comparison
/// decides separation first — cheaper than full SC (only SC is skipped; the
/// gate is not).
///
/// # Errors
///
/// Returns [`LevelMismatch`] when the operands fail the level gate, which runs
/// before the separation test.
pub fn merge(a: &Span, b: &Span) -> Result<Option<Span>, LevelMismatch> {
    let (ea, eb) = gated_endpoints(a, b)?;
    if separated(&ea, &eb) {
        return Ok(None);
    }
    let start = min(&ea.start, &eb.start).clone();
    let reach = max(&ea.reach, &eb.reach);
    Ok(Some(
        Span::from_endpoints(start, reach)
            .expect("non-separated gated operands give start < reach"),
    ))
}

/// The [`split`] rejection.
///
/// The level conditions run *first* (gate-first, design §6): `LevelMismatch`
/// wins when both fail.
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

/// Splits σ at an interior point (S4).
///
/// It returns `(start, p ⊖ start)` and `(p, reach ⊖ p)` — adjacent by
/// construction, widths composing to the whole (S5).
///
/// # Errors
///
/// It requires σ itself level-uniform (S4 — so `reach ⊖ p` shares the common
/// length) and `#start = #p` and `start < p < reach` (strictly interior: a
/// boundary `p` would mint a forbidden zero-width part, S2), **checked in
/// that order** (gate-first: both level conditions before interiority, so an
/// input failing both yields `LevelMismatch`, not `NotInterior`). A failed
/// level condition returns [`SplitError::LevelMismatch`]; a point that is not
/// strictly interior returns [`SplitError::NotInterior`].
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

/// Returns `⟦a⟧ \ ⟦b⟧` as ≤ 2 spans (S11d), the only op needing full SC.
///
/// | SC case | `⟦a⟧ \ ⟦b⟧` | spans
/// |---|---|---
/// | Separated / Adjacent | `⟦a⟧` | 1
/// | ProperOverlap, a starts first | left complement `[start a, start b)` | 1
/// | ProperOverlap, b starts first | right complement `[reach b, reach a)` | 1
/// | Containment, a ⊃ b | left + right complements | 1 or 2
/// | Containment, a ⊂ b / Equal | ∅ | 0
///
/// A coinciding boundary makes that complement zero-width; it fails WF and is
/// dropped — no algebra result ever carries a zero-width component span (S2).
/// The output is emitted in N1 order (left before right) and is normalized by
/// construction (§6).
///
/// # Errors
///
/// Returns [`LevelMismatch`] when the operands fail the level gate: the
/// dispatch runs after the unconditional gate.
pub fn difference(a: &Span, b: &Span) -> Result<SpanSet, LevelMismatch> {
    let (ea, eb) = gated_endpoints(a, b)?;
    // The left complement `[start a, start b)` and the right complement
    // `[reach b, reach a)` — each built only on an arm that has already
    // established that its endpoints increase.
    let left = || {
        Span::from_endpoints(ea.start.clone(), &eb.start)
            .expect("gated one-length endpoints with start a < start b")
    };
    let right = || {
        Span::from_endpoints(eb.reach.clone(), &ea.reach)
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
