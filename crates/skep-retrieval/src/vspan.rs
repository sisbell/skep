//! §Internal design — how M6 reads one request V-span: which subspace its
//! start names, and whether its shape is well-formed.

use std::sync::LazyLock;

use skep_address::{action_point, content_subspace, link_subspace, zeros, Nat, Span};

use crate::error::SpanFault;

// Content (s_C) / link (s_L) subspace numerals. M1 owns T7 and names them
// ([`content_subspace`]/[`link_subspace`]); M6 memoizes what M1 names, because
// `Nat = BigUint` cannot be `const` and a bare call would re-allocate a fresh
// `BigUint` on every reference. [`subspace_of`] only COMPARES against them —
// by reference, with no allocation — while the O(1)-per-query construction
// sites clone.

/// `s_C` = M1's content-subspace numeral (ASN-0047; T7 convention).
pub(crate) static S_C: LazyLock<Nat> = LazyLock::new(content_subspace);

/// `s_L` = M1's link-subspace numeral (ASN-0047; T7 convention).
pub(crate) static S_L: LazyLock<Nat> = LazyLock::new(link_subspace);

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

    fn t(comps: &[u32]) -> Tumbler {
        Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
    }

    fn span(start: &[u32], width: &[u32]) -> Span {
        Span::new(t(start), t(width)).expect("test spans are T12-valid")
    }

    #[test]
    fn the_subspace_numerals_are_m1s() {
        // M1 owns T7, so the numeral that decides content-from-link is read
        // from M1 and memoized here, never restated.
        assert_eq!(*S_C, content_subspace());
        assert_eq!(*S_L, link_subspace());
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
