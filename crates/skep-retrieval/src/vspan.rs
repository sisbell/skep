//! §Internal design — how M6 reads one request V-span: which subspace its
//! start names, and whether its shape is well-formed.

use std::sync::LazyLock;

use skep_address::{action_point, content_subspace, link_subspace, zeros, Nat, Span};
use skep_arrangement::VPos;

use crate::error::SpanFault;

// Content (s_C) / link (s_L) subspace numerals. M1 owns T7 and names them
// ([`content_subspace`]/[`link_subspace`]); M6 memoizes what M1 names, because
// `Nat = BigUint` cannot be `const` and a bare call would re-allocate a fresh
// `BigUint` on every reference. [`subspace_of`] only COMPARES against them —
// by reference, with no allocation — while the O(1)-per-query construction
// sites clone through [`Subspace::numeral`].
//
// Private, which is the point of [`Subspace`] carrying both directions: no
// file but this one names a raw subspace numeral, so a numeral cannot be
// handed to a function expecting a count.

/// `s_C` = M1's content-subspace numeral (ASN-0047; T7 convention).
static S_C: LazyLock<Nat> = LazyLock::new(content_subspace);

/// `s_L` = M1's link-subspace numeral (ASN-0047; T7 convention).
static S_L: LazyLock<Nat> = LazyLock::new(link_subspace);

/// Which of a document's two subspaces (T7; ASN-0047) a numeral names, or
/// `None` for a foreign one. `Nat` cannot appear in a pattern, so this is the
/// ONE place the two comparisons are written: every site that must tell
/// content from link matches on the answer instead of re-deriving the chain
/// and carrying its own fall-through.
///
/// `pub(crate)`, because M1 owns T7 and a second published subspace
/// vocabulary is exactly what memoizing M1's numerals avoids.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Subspace {
    Content,
    Link,
}

impl Subspace {
    /// The numeral M1 names this subspace by (T7) — the writing direction of
    /// [`subspace_of`], which reads one. The two sit together for the reason
    /// M5 keeps `ordinal_vspan` beside `is_ordinal_vspan`: a classification
    /// and the value it stands for are one definition read two ways, and they
    /// cannot come apart if neither is spelled anywhere else.
    ///
    /// Borrowed from the memoized static, so a caller that must own one
    /// clones at the O(1)-per-query site rather than on every comparison.
    pub(crate) fn numeral(self) -> &'static Nat {
        match self {
            Subspace::Content => &S_C,
            Subspace::Link => &S_L,
        }
    }
}

/// Classify a start subspace numeral (see [`Subspace`]).
fn subspace_of(s: &Nat) -> Option<Subspace> {
    if *s == *S_C {
        Some(Subspace::Content)
    } else if *s == *S_L {
        Some(Subspace::Link)
    } else {
        None
    }
}

/// The subspace a V-span's start names — position 1 of the start, classified.
///
/// TOTAL: `Tumbler` indexing is 1-based over a nonempty carrier, so every span
/// has a position 1 whatever its depth, gated or not. `None` therefore means
/// the numeral there is neither `s_C` nor `s_L`, NEVER that the start is too
/// shallow to name one — which is why COMPARE may ask this BEFORE
/// [`gate_vspan`] and still get an unambiguous answer, and why a one-component
/// start reports a foreign subspace rather than falling through some
/// depth-shaped hole.
pub(crate) fn span_subspace(span: &Span) -> Option<Subspace> {
    subspace_of(
        span.start()
            .get(1)
            .expect("a nonempty start has a position 1"),
    )
}

/// The V-position a span's start names — its first two components read as the
/// `[subspace, ordinal]` layout of a depth-2 V-position (ASN-0036 S8-depth),
/// which is where M6 states that layout and [`Subspace`] states half of it.
///
/// `None` iff the start carries fewer than two components, which
/// [`gate_vspan`]'s `#start ≥ 2` has already excluded for every gated span —
/// so a caller downstream of the gate is reading the total form of a settled
/// fact, not handling a case that arises. A deeper start reads its first two
/// components like any other: whether the position it names is one the
/// arrangement binds is M5's question, asked by `resolve`.
pub(crate) fn span_vpos(span: &Span) -> Option<VPos> {
    Some(VPos {
        subspace: span.start().get(1)?.clone(),
        ordinal: span.start().get(2)?.clone(),
    })
}

/// The SPAN half of ASN-0115's V-spec well-formedness: zero-free,
/// ordinal-level, level-uniform, depth `#start ≥ 2`. A V-spec is the pair
/// `ρ = (d, σ)`, so the other half — that `d` is a registered document — is
/// the per-operation registry gate, which raises its own typed rejection.
///
/// A span may fail several of the four at once, so which fault it reports is
/// fixed HERE and nowhere else — level-uniformity, then ordinal-level, then
/// zero-freedom, then depth, the first that fails being the one returned. That
/// is the whole of `SpanFault`'s precedence: its declaration order is a
/// vocabulary's, not this ladder's.
///
/// It deliberately does NOT gate depth-COMPATIBILITY (`#start == 2`):
/// ASN-0115 is explicit that depth-compatibility is a consulting-state
/// predicate, NOT a well-formedness condition, so a well-formed `#start ≥ 3`
/// span passes here and resolves to ⟨⟩ downstream (R6 silent-empty;
/// SHOWORIGIN_V alone rejects it, as its own WF_V(v) precondition).
pub(crate) fn gate_vspan(span: &Span) -> Result<(), SpanFault> {
    if !span.is_level_uniform() {
        return Err(SpanFault::NotLevelUniform); // #start == #width
    }
    if action_point(span.width()) != Some(span.width().len()) {
        return Err(SpanFault::NotOrdinalLevel); // width acts at deepest
    }
    if zeros(span.start()) != 0 {
        return Err(SpanFault::StartNotZeroFree); // ⇒ all components > 0
    }
    if span.start().len() < 2 {
        return Err(SpanFault::StartTooShallow); // ASN-0115 WF: #start ≥ 2
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Zero;
    use skep_address::Tumbler;
    use skep_arrangement::is_ordinal_vspan;

    fn t(comps: &[u32]) -> Tumbler {
        Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
    }

    fn span(start: &[u32], width: &[u32]) -> Span {
        Span::new(t(start), t(width)).expect("test spans are T12-valid")
    }

    #[test]
    fn the_subspace_numerals_are_m1s_and_the_two_directions_round_trip() {
        // M1 owns T7, so the numeral that decides content-from-link is read
        // from M1 and memoized here, never restated.
        assert_eq!(*Subspace::Content.numeral(), content_subspace());
        assert_eq!(*Subspace::Link.numeral(), link_subspace());
        // Writing a subspace and reading it back is the identity, which is
        // what makes `numeral` and `subspace_of` one definition rather than
        // two that happen to agree.
        for s in [Subspace::Content, Subspace::Link] {
            assert_eq!(subspace_of(s.numeral()), Some(s));
        }
    }

    #[test]
    fn subspace_of_classifies_the_two_real_subspaces_and_refuses_the_rest() {
        // The one place content-from-link is decided: every operation matches
        // on this answer rather than re-deriving the comparison chain.
        assert_eq!(subspace_of(&content_subspace()), Some(Subspace::Content));
        assert_eq!(subspace_of(&link_subspace()), Some(Subspace::Link));
        assert_eq!(subspace_of(&Nat::from(3u32)), None);
        assert_eq!(subspace_of(&Nat::zero()), None);
    }

    #[test]
    fn gate_vspan_admits_wellformed_spans_of_any_depth_at_least_2() {
        // ASN-0115 WF admits #start ≥ 2; a #start ≥ 3 span is well-formed
        // (depth-COMPATIBILITY is consulting-state, gated elsewhere).
        assert!(gate_vspan(&span(&[1, 1], &[0, 3])).is_ok());
        assert!(gate_vspan(&span(&[2, 1], &[0, 1])).is_ok());
        assert!(gate_vspan(&span(&[1, 1, 1], &[0, 0, 1])).is_ok());
        // A foreign start subspace is not a WELL-FORMEDNESS matter either.
        assert!(gate_vspan(&span(&[3, 1], &[0, 1])).is_ok());
    }

    #[test]
    fn gate_vspan_rejects_each_fault_in_documented_order() {
        // Level-uniformity is checked before ordinal-level: a [1]-width on a
        // depth-2 start fails BOTH, and NotLevelUniform wins.
        assert_eq!(
            gate_vspan(&span(&[1, 1], &[1])),
            Err(SpanFault::NotLevelUniform)
        );
        // Level-uniform but action point 1 ≠ 2: not ordinal-level.
        assert_eq!(
            gate_vspan(&span(&[1, 1], &[1, 0])),
            Err(SpanFault::NotOrdinalLevel)
        );
        // Ordinal-level and uniform, but the start carries a separator.
        assert_eq!(
            gate_vspan(&span(&[1, 0, 1], &[0, 0, 1])),
            Err(SpanFault::StartNotZeroFree)
        );
        // Everything else passes, but #start = 1 < 2.
        assert_eq!(
            gate_vspan(&span(&[5], &[1])),
            Err(SpanFault::StartTooShallow)
        );
    }

    #[test]
    fn a_gated_span_has_m5s_shape_exactly_when_its_start_is_depth_2() {
        // What lets SHOWORIGIN_V put WF_V(v) to M5's `is_ordinal_vspan`
        // instead of measuring the start itself: after this gate, DEPTH is the
        // only clause of M5's shape still open. Level-uniformity ties #width
        // to #start and ordinal-level puts the width's one nonzero component
        // last, so a gated depth-2 span IS `[s, o] × [0, n≥1]`, and every
        // deeper gated span fails M5's shape on depth alone.
        for (start, width) in [
            (&[1u32, 1][..], &[0u32, 3][..]),
            (&[2, 4], &[0, 1]),
            (&[3, 1], &[0, 1]), // a foreign subspace is still this SHAPE
        ] {
            let s = span(start, width);
            assert!(gate_vspan(&s).is_ok());
            assert!(is_ordinal_vspan(&s), "gated depth-2 ⇒ M5 serves it");
        }
        for (start, width) in [
            (&[1u32, 1, 1][..], &[0u32, 0, 1][..]),
            (&[1, 1, 1, 1], &[0, 0, 0, 2]),
        ] {
            let s = span(start, width);
            assert!(gate_vspan(&s).is_ok(), "deeper spans are WELL-FORMED");
            assert!(!is_ordinal_vspan(&s), "…and M5 declines them, on depth");
        }
    }

    #[test]
    fn span_vpos_reads_the_two_components_a_gated_start_carries() {
        // The depth-2 layout is read HERE and written back by COMPARE's sort
        // key, so the two directions name each other rather than each
        // extracting components on their own.
        assert_eq!(
            span_vpos(&span(&[1, 7], &[0, 3])),
            Some(VPos {
                subspace: Nat::from(1u32),
                ordinal: Nat::from(7u32),
            })
        );
        // A deeper start reads its FIRST TWO components like any other — what
        // the position it names resolves to is M5's question.
        assert_eq!(
            span_vpos(&span(&[2, 4, 9], &[0, 0, 1])),
            Some(VPos {
                subspace: Nat::from(2u32),
                ordinal: Nat::from(4u32),
            })
        );
        // The one `None`, and the gate has already refused it
        // (`StartTooShallow`), which is why its callers may treat the read as
        // total.
        let shallow = span(&[5], &[1]);
        assert_eq!(span_vpos(&shallow), None);
        assert_eq!(gate_vspan(&shallow), Err(SpanFault::StartTooShallow));
    }

    #[test]
    fn span_subspace_is_total_over_every_span_including_the_shallowest() {
        // Position 1 of a start exists at EVERY depth — `Tumbler` indexing is
        // 1-based over a nonempty carrier — so this answers for a span the
        // gate would reject and for one it would not, alike. A `None` here
        // means "foreign numeral", never "too shallow to have one", which is
        // what lets COMPARE ask it before gating.
        assert_eq!(
            span_subspace(&span(&[1, 1], &[0, 3])),
            Some(Subspace::Content)
        );
        assert_eq!(span_subspace(&span(&[2, 1], &[0, 1])), Some(Subspace::Link));
        assert_eq!(
            span_subspace(&span(&[1, 1, 1], &[0, 0, 1])),
            Some(Subspace::Content)
        );
        assert_eq!(span_subspace(&span(&[3, 1], &[0, 1])), None);
        // Depth 1: too shallow for the gate (`StartTooShallow`), and still an
        // unambiguous subspace reading.
        assert_eq!(span_subspace(&span(&[1], &[1])), Some(Subspace::Content));
        assert_eq!(span_subspace(&span(&[5], &[1])), None);
    }
}
