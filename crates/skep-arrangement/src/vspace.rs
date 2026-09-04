//! §Request-side V-space values — the depth-2 V-position ([`VPos`]), COPY's
//! source specification ([`VSpec`]), and the ordinal-level depth-2 V-range
//! stated once from both sides: [`as_ordinal_vspan`] reads one (and
//! [`is_ordinal_vspan`] is its verdict), [`ordinal_vspan`] builds one.

use num_traits::Zero;
use skep_address::{Address, Nat, Span, Tumbler};

/// A depth-2 V-position `[subspace, ordinal]` (m = 2 — ASN-0036 S8-depth;
/// structurally depth-2, so "depth" needs no separate check).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VPos {
    /// s_C = 1 (content) or s_L = 2 (link), per ASN-0047.
    pub subspace: Nat,
    /// 1-based ordinal within the subspace.
    pub ordinal: Nat,
}

/// One source-span for COPY (ASN-0118): transclude `span` of `source`'s
/// arrangement. The span must satisfy [`is_ordinal_vspan`] and lie in the
/// content subspace (`BadSpan`/`SourceNotContentSubspace` otherwise —
/// Conflicts #7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VSpec {
    pub source: Address,
    pub span: Span,
}

/// The three quantities an ordinal-level depth-2 V-span names, borrowed from
/// the span [`as_ordinal_vspan`] read them out of. Holding them is what lets
/// a caller that has already asked whether a span has this shape go on to use
/// its parts, with no second extraction to justify.
///
/// Named fields, not a tuple: all three are `&Nat`, so a positional
/// destructuring would put them back within swapping distance of each other.
pub(crate) struct OrdinalVSpan<'a> {
    /// The subspace numeral, `start.get(1)`.
    pub(crate) subspace: &'a Nat,
    /// The first named ordinal, `start.get(2)`.
    pub(crate) ordinal: &'a Nat,
    /// How many consecutive positions the span names, `width.get(2)`.
    pub(crate) count: &'a Nat,
}

/// Read `span` as an ordinal-level depth-2 V-range — a count of positions
/// within one subspace (ASN-0118 action point 2) — or `None` when it is not
/// one. THE ONE DEFINITION of that shape in M5, which is why its two verdicts
/// cannot drift apart: [`M5State::resolve`](crate::M5State::resolve) folds a
/// span this refuses to ⟨⟩, and COPY rejects the same span as
/// [`CopyError::BadSpan`](crate::CopyError::BadSpan).
///
/// The condition is stated in full on [`is_ordinal_vspan`], the published
/// half. Handing back the parts is what lets both callers read the subspace,
/// ordinal and count off a span whose shape is already settled, instead of
/// re-extracting components behind an `.expect` apiece.
pub(crate) fn as_ordinal_vspan(span: &Span) -> Option<OrdinalVSpan<'_>> {
    let (start, width) = (span.start(), span.width());
    if start.len() != 2 || width.len() != 2 || !width.get(1).is_some_and(|w| w.is_zero()) {
        return None;
    }
    Some(OrdinalVSpan {
        subspace: start.get(1)?,
        ordinal: start.get(2)?,
        count: width.get(2)?,
    })
}

/// Does `span` name an ordinal-level depth-2 V-range — a count of positions
/// within one subspace (ASN-0118 action point 2)? The COMPLETE condition is
/// `#start == 2 ∧ #width == 2 ∧ width.get(1) == 0`: a span with `#start ≠ 2`
/// (below or above), a `#width ≠ 2`, or a level-uniform `[m, n]` width with
/// `m > 0` (action-point-1, which makes `width.get(2)` the wrong extraction)
/// each fail it.
///
/// Published so a caller building V-spans from a request can pre-validate and
/// tell "bad request" from "genuinely empty" before it asks. The published
/// half is the predicate because that is the whole of the question a caller
/// asks from outside: whether the request it holds is usable — a verdict, not
/// a decomposition. What [`ordinal_vspan`] builds, this accepts.
pub fn is_ordinal_vspan(span: &Span) -> bool {
    as_ordinal_vspan(span).is_some()
}

/// `count` positions starting AT the V-position `at`, as the span
/// [`is_ordinal_vspan`] recognizes — the constructing half of that one shape,
/// so a producer of V-spans and its recognizer cannot come apart.
///
/// The start is a [`VPos`] rather than a loose subspace/ordinal pair because
/// those two are one thing — the position the range opens at — and as two
/// same-typed arguments they could be handed over swapped, which builds a
/// well-formed span naming a subspace that selects nothing and reports as
/// emptiness far downstream.
///
/// `None` iff `count == 0`: M1's T12 rejects a zero-width span outright, the
/// empty designation being `SpanSet::empty()` rather than a degenerate span.
/// Every other argument yields a span, `at`'s components being unconstrained
/// naturals here — whether the subspace numeral selects a run-list is the
/// arrangement's question, answered where it is asked.
pub fn ordinal_vspan(at: &VPos, count: &Nat) -> Option<Span> {
    if count.is_zero() {
        return None;
    }
    let start = Tumbler::new([at.subspace.clone(), at.ordinal.clone()])
        .expect("a two-component sequence is nonempty");
    let width = Tumbler::new([Nat::zero(), count.clone()])
        .expect("a two-component sequence is nonempty");
    Some(Span::new(start, width).expect("count ≥ 1 at action point 2 ⇒ T12-valid"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{n, t, vp, vspan};

    #[test]
    fn what_the_constructor_builds_the_reader_reads_back() {
        // The two halves of one shape: anything ordinal_vspan yields is an
        // ordinal-level depth-2 V-span, in either subspace — and reading it
        // recovers exactly the three quantities it was built from.
        for (sub, ord, count) in [(1u32, 1u32, 1u32), (1, 7, 4), (2, 1, 9)] {
            let s = ordinal_vspan(&vp(sub, ord), &n(count)).expect("count ≥ 1");
            assert!(is_ordinal_vspan(&s));
            assert_eq!(s.start(), &t(&[sub, ord]));
            assert_eq!(s.width(), &t(&[0, count]));
            let v = as_ordinal_vspan(&s).expect("what the constructor builds, the reader reads");
            assert_eq!((v.subspace, v.ordinal, v.count), (&n(sub), &n(ord), &n(count)));
        }
        // Zero positions is not a span: ⟨⟩ designates nothing, T12 has no
        // zero-width value to hand back.
        assert!(ordinal_vspan(&vp(1, 1), &n(0)).is_none());
    }

    #[test]
    fn a_v_position_is_its_subspace_and_ordinal_in_that_order() {
        // Why the constructor takes a VPos and not two naturals: the two
        // components are not interchangeable, and a transposed pair names a
        // different position rather than failing.
        assert_eq!(vp(1, 2), vp(1, 2));
        assert_ne!(vp(1, 2), vp(2, 1));
        assert_ne!(
            ordinal_vspan(&vp(1, 2), &n(1)),
            ordinal_vspan(&vp(2, 1), &n(1))
        );
    }

    #[test]
    fn the_ordinal_vspan_shape_is_exactly_the_three_clauses() {
        // §2/§5: the usable form, and each way of failing it.
        // The link subspace is as usable a shape as the content one.
        assert!(is_ordinal_vspan(&vspan(1, 1, 3)));
        assert!(is_ordinal_vspan(&vspan(2, 4, 1)));
        // #start ≠ 2, below and above.
        let shallow = Span::new(t(&[5]), t(&[1])).expect("T12");
        assert!(!is_ordinal_vspan(&shallow));
        let deep = Span::new(t(&[1, 1, 1]), t(&[0, 0, 1])).expect("T12");
        assert!(!is_ordinal_vspan(&deep));
        // #width ≠ 2 alone, with the other two clauses satisfied. T12 admits
        // this span — action point 2 ≤ #start 2 — and its start is a
        // well-formed V-position with a zero at width position 1, so only
        // `#width == 2` stands between it and being read as five ordinals
        // from [1, 1]. Its reach is [1, 6, 0]: it names something else.
        let deep_width = Span::new(t(&[1, 1]), t(&[0, 5, 0])).expect("T12: action point 2 ≤ #start");
        assert!(!is_ordinal_vspan(&deep_width));
        // A level-uniform [m, n] width with m > 0 is action-point-1.
        let level_uniform = Span::new(t(&[1, 1]), t(&[1, 0])).expect("T12");
        assert!(!is_ordinal_vspan(&level_uniform));
    }
}
